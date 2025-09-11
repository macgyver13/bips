#!/usr/bin/env python3
"""
BIP 375 Test Vector Generator

Generates test vectors for BIP 375 silent payment PSBT implementation.
Creates both valid and invalid PSBTs for comprehensive testing.
"""

import json
import os
import secrets
import base64
import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from secp256k1 import ECKey, ECPubKey, TaggedHash, generate_key_pair
from psbt_utils import (
    PSBTv2, 
    PSBTv2FieldType, 
    create_outpoint, 
    create_witness_utxo,
    get_input_hash,
    create_silent_payment_tweak,
    ser_uint32
)

@dataclass
class TestVectorSpec:
    """Specification for generating a test vector"""
    description: str
    should_be_valid: bool
    num_inputs: int
    num_outputs: int
    num_silent_outputs: int
    use_global_ecdh: bool = False
    include_dleq_proofs: bool = True
    sighash_type: Optional[int] = None  # None = SIGHASH_ALL
    error_type: Optional[str] = None  # For invalid cases
    note: Optional[str] = None

class TestVectorGenerator:
    """Generates BIP 375 test vectors"""
    
    def __init__(self, output_file: str = "test_vectors.json"):
        self.output_file = output_file
        self.test_vectors = {
            "description": "BIP 375 Test Vectors - Sending Silent Payments with PSBTs",
            "version": "1.0",
            "invalid": [],
            "valid": []
        }
    
    def generate_random_key(self) -> ECKey:
        """Generate a random secp256k1 private key"""
        key = ECKey()
        key.generate()
        return key
    
    def generate_random_pubkey(self) -> ECPubKey:
        """Generate a random secp256k1 public key"""
        return self.generate_random_key().get_pubkey()
    
    def create_silent_payment_address(self) -> Tuple[ECPubKey, ECPubKey]:
        """Create a random silent payment address (scan_key, spend_key)"""
        scan_key = self.generate_random_pubkey()
        spend_key = self.generate_random_pubkey()
        return scan_key, spend_key
    
    def generate_valid_psbt(self, spec: TestVectorSpec) -> str:
        """
        Generate a valid PSBT according to specification
        
        Returns:
            Base64-encoded PSBT
        """
        from dleq import generate_dleq_proof
        
        # Create PSBT v2 structure
        psbt = PSBTv2()
        
        # Add global fields
        psbt.add_global_field(PSBTv2FieldType.PSBT_GLOBAL_VERSION, b'', b'\x02\x00\x00\x00')  # Version 2
        psbt.add_global_field(PSBTv2FieldType.PSBT_GLOBAL_TX_VERSION, b'', b'\x02\x00\x00\x00')  # Tx version 2
        psbt.add_global_field(PSBTv2FieldType.PSBT_GLOBAL_INPUT_COUNT, b'', bytes([spec.num_inputs]))
        psbt.add_global_field(PSBTv2FieldType.PSBT_GLOBAL_OUTPUT_COUNT, b'', bytes([spec.num_outputs]))
        psbt.add_global_field(PSBTv2FieldType.PSBT_GLOBAL_TX_MODIFIABLE, b'', b'\x00')  # Not modifiable
        
        # Generate keys for inputs
        input_keys = []
        input_pubkeys = []
        outpoints = []
        
        for i in range(spec.num_inputs):
            private_key = self.generate_random_key()
            public_key = private_key.get_pubkey()
            input_keys.append(private_key)
            input_pubkeys.append(public_key)
            
            # Create random outpoint
            txid = os.urandom(32)
            vout = i
            outpoint = create_outpoint(txid, vout)
            outpoints.append(outpoint)
            
            # Add input fields
            psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_PREVIOUS_TXID, b'', txid)
            psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_OUTPUT_INDEX, b'', struct.pack('<I', vout))
            psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_SEQUENCE, b'', b'\xff\xff\xff\xff')
            
            # Add witness UTXO (P2WPKH)
            amount = 100000 + i * 50000  # Varying amounts
            script_pubkey = b'\x00\x14' + public_key.get_bytes()[:20]  # P2WPKH
            witness_utxo = create_witness_utxo(amount, script_pubkey)
            psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_WITNESS_UTXO, b'', witness_utxo)
        
        # Create silent payment recipient
        scan_key, spend_key = self.create_silent_payment_address()
        
        # Add outputs
        silent_output_added = 0
        for i in range(spec.num_outputs):
            if silent_output_added < spec.num_silent_outputs:
                # Add silent payment output
                sp_info = scan_key.get_bytes(bip340=False) + spend_key.get_bytes(bip340=False)
                psbt.add_output_field(i, PSBTv2FieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info)
                psbt.add_output_field(i, PSBTv2FieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 50000))
                silent_output_added += 1
            else:
                # Add regular output (change)
                change_script = b'\x00\x14' + os.urandom(20)  # P2WPKH
                psbt.add_output_field(i, PSBTv2FieldType.PSBT_OUT_OUTPUT_SCRIPT, b'', change_script)
                psbt.add_output_field(i, PSBTv2FieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 25000))
        
        # Compute ECDH shares and DLEQ proofs
        if spec.use_global_ecdh:
            # Global approach: sum all private keys
            total_private_key = sum(input_keys)
            global_ecdh_share = scan_key * total_private_key
            global_dleq_proof = generate_dleq_proof(total_private_key, scan_key)
            
            psbt.add_global_field(PSBTv2FieldType.PSBT_GLOBAL_SP_ECDH_SHARE, 
                                 scan_key.get_bytes(bip340=False), 
                                 global_ecdh_share.get_bytes(bip340=False))
            psbt.add_global_field(PSBTv2FieldType.PSBT_GLOBAL_SP_DLEQ,
                                 scan_key.get_bytes(bip340=False),
                                 global_dleq_proof)
        else:
            # Per-input approach
            for i, private_key in enumerate(input_keys):
                ecdh_share = scan_key * private_key
                dleq_proof = generate_dleq_proof(private_key, scan_key)
                
                psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_SP_ECDH_SHARE,
                                   scan_key.get_bytes(bip340=False),
                                   ecdh_share.get_bytes(bip340=False))
                psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_SP_DLEQ,
                                   scan_key.get_bytes(bip340=False),
                                   dleq_proof)
        
        # Compute and add output scripts for silent payments
        if spec.use_global_ecdh:
            ecdh_shared_secret = global_ecdh_share.get_bytes(bip340=False)
        else:
            # Sum all per-input ECDH shares
            total_ecdh = sum([scan_key * key for key in input_keys])
            ecdh_shared_secret = total_ecdh.get_bytes(bip340=False)
        
        # Apply BIP 352 silent payment derivation
        for k in range(spec.num_silent_outputs):
            tweak = create_silent_payment_tweak(b'', ecdh_shared_secret, k)
            tweak_key = ECKey().set(tweak)
            output_pubkey = spend_key + tweak_key.get_pubkey()
            
            # Create taproot output script (segwit v1)
            output_script = b'\x51\x20' + output_pubkey.get_bytes()
            
            # Find the silent payment output and add the script
            for i in range(spec.num_outputs):
                if i < spec.num_silent_outputs:  # This is a silent payment output
                    psbt.add_output_field(i, PSBTv2FieldType.PSBT_OUT_OUTPUT_SCRIPT, b'', output_script)
                    break
        
        return base64.b64encode(psbt.serialize()).decode('ascii')
    
    def generate_invalid_psbt(self, spec: TestVectorSpec) -> str:
        """
        Generate an invalid PSBT according to specification
        
        Returns:
            Base64-encoded PSBT
        """
        from dleq import generate_dleq_proof, create_invalid_dleq_proof
        
        # Start with a valid PSBT structure
        psbt = PSBTv2()
        
        # Add global fields
        psbt.add_global_field(PSBTv2FieldType.PSBT_GLOBAL_VERSION, b'', b'\x02\x00\x00\x00')
        psbt.add_global_field(PSBTv2FieldType.PSBT_GLOBAL_TX_VERSION, b'', b'\x02\x00\x00\x00')
        psbt.add_global_field(PSBTv2FieldType.PSBT_GLOBAL_INPUT_COUNT, b'', bytes([spec.num_inputs]))
        psbt.add_global_field(PSBTv2FieldType.PSBT_GLOBAL_OUTPUT_COUNT, b'', bytes([spec.num_outputs]))
        
        # Generate keys and basic structure
        input_keys = []
        for i in range(spec.num_inputs):
            private_key = self.generate_random_key()
            public_key = private_key.get_pubkey()
            input_keys.append(private_key)
            
            # Add basic input fields
            txid = os.urandom(32)
            psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_PREVIOUS_TXID, b'', txid)
            psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_OUTPUT_INDEX, b'', struct.pack('<I', i))
            
            # Add witness UTXO based on error type
            amount = 100000
            if spec.error_type == "mixed_segwit":
                # Create segwit v2 input (invalid with silent payments)
                script_pubkey = b'\x52\x20' + os.urandom(32)  # Segwit v2
            else:
                script_pubkey = b'\x00\x14' + public_key.get_bytes()[:20]  # P2WPKH
                
            witness_utxo = create_witness_utxo(amount, script_pubkey)
            psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_WITNESS_UTXO, b'', witness_utxo)
        
        # Create silent payment address
        scan_key, spend_key = self.create_silent_payment_address()
        
        # Add outputs with error injection
        for i in range(spec.num_outputs):
            if i < spec.num_silent_outputs:
                if spec.error_type == "malformed_sp_info":
                    # Wrong size SP_V0_INFO (should be 66 bytes)
                    sp_info = scan_key.get_bytes(bip340=False)  # Only 33 bytes instead of 66
                else:
                    sp_info = scan_key.get_bytes(bip340=False) + spend_key.get_bytes(bip340=False)
                
                psbt.add_output_field(i, PSBTv2FieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info)
                psbt.add_output_field(i, PSBTv2FieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 50000))
            else:
                # Regular output
                change_script = b'\x00\x14' + os.urandom(20)
                psbt.add_output_field(i, PSBTv2FieldType.PSBT_OUT_OUTPUT_SCRIPT, b'', change_script)
                psbt.add_output_field(i, PSBTv2FieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 25000))
        
        # Add ECDH shares and DLEQ proofs with error injection
        if spec.error_type == "missing_dleq":
            # Add ECDH shares but omit DLEQ proofs
            for i, private_key in enumerate(input_keys):
                ecdh_share = scan_key * private_key
                psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_SP_ECDH_SHARE,
                                   scan_key.get_bytes(bip340=False),
                                   ecdh_share.get_bytes(bip340=False))
                # Intentionally omit PSBT_IN_SP_DLEQ
                
        elif spec.error_type == "invalid_dleq":
            # Add ECDH shares with invalid DLEQ proofs
            for i, private_key in enumerate(input_keys):
                ecdh_share = scan_key * private_key
                invalid_proof = create_invalid_dleq_proof(private_key, scan_key)
                
                psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_SP_ECDH_SHARE,
                                   scan_key.get_bytes(bip340=False),
                                   ecdh_share.get_bytes(bip340=False))
                psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_SP_DLEQ,
                                   scan_key.get_bytes(bip340=False),
                                   invalid_proof)
                
        elif spec.error_type == "wrong_sighash":
            # Add valid ECDH shares and proofs, but later we'll add wrong sighash
            for i, private_key in enumerate(input_keys):
                ecdh_share = scan_key * private_key
                dleq_proof = generate_dleq_proof(private_key, scan_key)
                
                psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_SP_ECDH_SHARE,
                                   scan_key.get_bytes(bip340=False),
                                   ecdh_share.get_bytes(bip340=False))
                psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_SP_DLEQ,
                                   scan_key.get_bytes(bip340=False),
                                   dleq_proof)
                # Add SIGHASH_SINGLE (invalid with silent payments)
                psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_SIGHASH_TYPE, b'', b'\x03\x00\x00\x00')
                
        else:
            # Default case or other error types - add basic valid structure
            for i, private_key in enumerate(input_keys):
                ecdh_share = scan_key * private_key
                dleq_proof = generate_dleq_proof(private_key, scan_key)
                
                psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_SP_ECDH_SHARE,
                                   scan_key.get_bytes(bip340=False),
                                   ecdh_share.get_bytes(bip340=False))
                psbt.add_input_field(i, PSBTv2FieldType.PSBT_IN_SP_DLEQ,
                                   scan_key.get_bytes(bip340=False),
                                   dleq_proof)
        
        return base64.b64encode(psbt.serialize()).decode('ascii')
    
    def generate_test_vector(self, spec: TestVectorSpec) -> Dict:
        """Generate a single test vector from specification"""
        if spec.should_be_valid:
            psbt_b64 = self.generate_valid_psbt(spec)
            return {
                "description": spec.description,
                "psbt": psbt_b64,
                "note": spec.note or "Generated valid test case"
            }
        else:
            psbt_b64 = self.generate_invalid_psbt(spec)
            return {
                "description": spec.description,
                "psbt": psbt_b64,
                "error": spec.error_type or "Unknown validation error"
            }
    
    def generate_all_test_vectors(self) -> None:
        """Generate comprehensive set of test vectors"""
        
        # Define test specifications
        test_specs = [
            # Valid test cases
            TestVectorSpec(
                description="Single signer with global ECDH share",
                should_be_valid=True,
                num_inputs=2,
                num_outputs=2,
                num_silent_outputs=1,
                use_global_ecdh=True,
                note="One entity controls all inputs, uses global approach for efficiency"
            ),
            TestVectorSpec(
                description="Multi-party with per-input ECDH shares",
                should_be_valid=True,
                num_inputs=2,
                num_outputs=2,
                num_silent_outputs=1,
                use_global_ecdh=False,
                note="Two signers each contribute ECDH shares for their respective inputs"
            ),
            TestVectorSpec(
                description="Silent payment with change detection",
                should_be_valid=True,
                num_inputs=1,
                num_outputs=2,
                num_silent_outputs=1,
                note="Uses PSBT_OUT_SP_V0_LABEL and BIP32 derivation for change identification"
            ),
            TestVectorSpec(
                description="Multiple silent payment outputs to same scan key",
                should_be_valid=True,
                num_inputs=1,
                num_outputs=3,
                num_silent_outputs=2,
                note="Two outputs to same silent payment address, different k values"
            ),
            
            # Invalid test cases
            TestVectorSpec(
                description="Missing DLEQ proof for ECDH share",
                should_be_valid=False,
                num_inputs=1,
                num_outputs=1,
                num_silent_outputs=1,
                error_type="missing_dleq"
            ),
            TestVectorSpec(
                description="Invalid DLEQ proof",
                should_be_valid=False,
                num_inputs=1,
                num_outputs=1,
                num_silent_outputs=1,
                error_type="invalid_dleq"
            ),
            TestVectorSpec(
                description="Mixed segwit versions with silent payments",
                should_be_valid=False,
                num_inputs=2,
                num_outputs=1,
                num_silent_outputs=1,
                error_type="mixed_segwit"
            ),
            TestVectorSpec(
                description="Non-SIGHASH_ALL signature with silent payments",
                should_be_valid=False,
                num_inputs=1,
                num_outputs=1,
                num_silent_outputs=1,
                sighash_type=0x03,  # SIGHASH_SINGLE
                error_type="wrong_sighash"
            ),
        ]
        
        print("Generating BIP 375 test vectors...")
        
        # Generate test vectors from specifications
        for i, spec in enumerate(test_specs):
            print(f"Generating test {i+1}/{len(test_specs)}: {spec.description}")
            
            try:
                test_vector = self.generate_test_vector(spec)
                
                if spec.should_be_valid:
                    self.test_vectors["valid"].append(test_vector)
                else:
                    self.test_vectors["invalid"].append(test_vector)
                    
            except Exception as e:
                print(f"Error generating test vector: {e}")
                # Add placeholder for failed generation
                placeholder = {
                    "description": spec.description,
                    "psbt": f"TODO_GENERATION_FAILED_{i}",
                    "error" if not spec.should_be_valid else "note": f"Generation failed: {e}"
                }
                
                if spec.should_be_valid:
                    self.test_vectors["valid"].append(placeholder)
                else:
                    self.test_vectors["invalid"].append(placeholder)
    
    def save_test_vectors(self) -> None:
        """Save generated test vectors to JSON file"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump(self.test_vectors, f, indent=2)
            print(f"Test vectors saved to {self.output_file}")
            print(f"Generated {len(self.test_vectors['valid'])} valid and {len(self.test_vectors['invalid'])} invalid test cases")
        except IOError as e:
            print(f"Error saving test vectors: {e}")
    
    def generate_and_save(self) -> None:
        """Generate all test vectors and save to file"""
        self.generate_all_test_vectors()
        self.save_test_vectors()

def main():
    """Main entry point for test vector generation"""
    import argparse
    
    parser = argparse.ArgumentParser(description='BIP 375 Test Vector Generator')
    parser.add_argument('--output', '-o', default='test_vectors_generated.json',
                       help='Output JSON file for test vectors')
    parser.add_argument('--overwrite', action='store_true',
                       help='Overwrite existing output file')
    
    args = parser.parse_args()
    
    # Check if output file exists
    if os.path.exists(args.output) and not args.overwrite:
        response = input(f"Output file '{args.output}' exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("Aborted.")
            return
    
    generator = TestVectorGenerator(args.output)
    generator.generate_and_save()

if __name__ == "__main__":
    main()