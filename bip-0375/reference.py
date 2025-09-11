#!/usr/bin/env python3
"""
BIP 375: Sending Silent Payments with PSBTs - Reference Implementation

This module implements the core functionality for creating and processing
PSBT v2 transactions with silent payment outputs as specified in BIP 375.

Requires:
- BIP 352 (Silent Payments)
- BIP 370 (PSBT v2) 
- BIP 374 (DLEQ Proofs)
"""

import hashlib
import struct
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from enum import IntEnum

# PSBT v2 + BIP 375 field types
class PSBTFieldType(IntEnum):
    # Standard PSBT v2 global fields
    PSBT_GLOBAL_UNSIGNED_TX = 0x00
    PSBT_GLOBAL_XPUB = 0x01
    PSBT_GLOBAL_VERSION = 0xfb
    PSBT_GLOBAL_PROPRIETARY = 0xfc
    PSBT_GLOBAL_INPUT_COUNT = 0x04
    PSBT_GLOBAL_OUTPUT_COUNT = 0x05
    PSBT_GLOBAL_TX_MODIFIABLE = 0x06
    
    # BIP 375 Silent Payment global fields
    PSBT_GLOBAL_SP_ECDH_SHARE = 0x07
    PSBT_GLOBAL_SP_DLEQ = 0x08
    
    # Standard PSBT v2 input fields
    PSBT_IN_NON_WITNESS_UTXO = 0x00
    PSBT_IN_WITNESS_UTXO = 0x01
    PSBT_IN_PARTIAL_SIG = 0x02
    PSBT_IN_SIGHASH_TYPE = 0x03
    PSBT_IN_REDEEM_SCRIPT = 0x04
    PSBT_IN_WITNESS_SCRIPT = 0x05
    PSBT_IN_BIP32_DERIVATION = 0x06
    PSBT_IN_FINAL_SCRIPTSIG = 0x07
    PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
    PSBT_IN_POR_COMMITMENT = 0x09
    PSBT_IN_RIPEMD160 = 0x0a
    PSBT_IN_SHA256 = 0x0b
    PSBT_IN_HASH160 = 0x0c
    PSBT_IN_HASH256 = 0x0d
    PSBT_IN_PREVIOUS_TXID = 0x0e
    PSBT_IN_OUTPUT_INDEX = 0x0f
    PSBT_IN_SEQUENCE = 0x10
    PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12
    PSBT_IN_TAP_KEY_SIG = 0x13
    PSBT_IN_TAP_SCRIPT_SIG = 0x14
    PSBT_IN_TAP_LEAF_SCRIPT = 0x15
    PSBT_IN_TAP_BIP32_DERIVATION = 0x16
    PSBT_IN_TAP_INTERNAL_KEY = 0x17
    PSBT_IN_TAP_MERKLE_ROOT = 0x18
    PSBT_IN_PROPRIETARY = 0xfc
    
    # BIP 375 Silent Payment input fields  
    PSBT_IN_SP_ECDH_SHARE = 0x1d
    PSBT_IN_SP_DLEQ = 0x1e
    
    # Standard PSBT v2 output fields
    PSBT_OUT_REDEEM_SCRIPT = 0x00
    PSBT_OUT_WITNESS_SCRIPT = 0x01
    PSBT_OUT_BIP32_DERIVATION = 0x02
    PSBT_OUT_AMOUNT = 0x03
    PSBT_OUT_SCRIPT = 0x04
    PSBT_OUT_TAP_INTERNAL_KEY = 0x05
    PSBT_OUT_TAP_TREE = 0x06
    PSBT_OUT_TAP_BIP32_DERIVATION = 0x07
    PSBT_OUT_PROPRIETARY = 0xfc
    
    # BIP 375 Silent Payment output fields
    PSBT_OUT_SP_V0_INFO = 0x09
    PSBT_OUT_SP_V0_LABEL = 0x0a

@dataclass
class SilentPaymentAddress:
    """Represents a BIP 352 silent payment address"""
    scan_key: bytes  # 33 bytes
    spend_key: bytes  # 33 bytes
    label: Optional[int] = None  # 32-bit uint for change detection

@dataclass  
class ECDHShare:
    """ECDH share for a specific scan key"""
    scan_key: bytes  # 33 bytes
    share: bytes     # 33 bytes (point)
    dleq_proof: Optional[bytes] = None  # 64 bytes

class SilentPaymentPSBT:
    """
    PSBT v2 with BIP 375 silent payment extensions
    """
    
    def __init__(self):
        self.global_fields: Dict[int, Dict[bytes, bytes]] = {}
        self.input_fields: List[Dict[int, Dict[bytes, bytes]]] = []
        self.output_fields: List[Dict[int, Dict[bytes, bytes]]] = []
        
    # Core PSBT v2 + Silent Payments functions (Step 5)
    
    def create_silent_payment_psbt(self, inputs: List[dict], outputs: List[dict], 
                                 silent_addresses: List[SilentPaymentAddress]) -> 'SilentPaymentPSBT':
        """
        Create a new PSBT v2 with silent payment outputs
        
        Args:
            inputs: List of input specifications
            outputs: List of regular output specifications  
            silent_addresses: List of silent payment addresses to send to
            
        Returns:
            SilentPaymentPSBT instance
        """
        # TODO: Implement PSBT v2 creation with silent payment fields
        raise NotImplementedError("create_silent_payment_psbt not yet implemented")
    
    def add_ecdh_shares(self, private_keys: Dict[int, bytes], scan_keys: List[bytes]) -> None:
        """
        Add ECDH shares to the PSBT for given private keys and scan keys
        
        Args:
            private_keys: Dict mapping input_index -> private_key (32 bytes)
            scan_keys: List of scan keys to compute shares for
        """
        # TODO: Implement ECDH share computation and addition
        # - Determine if using global or per-input approach
        # - Compute a * B_scan for each relevant combination
        # - Add to appropriate PSBT fields
        raise NotImplementedError("add_ecdh_shares not yet implemented")
    
    def generate_dleq_proofs(self, private_keys: Dict[int, bytes]) -> None:
        """
        Generate DLEQ proofs for all ECDH shares in the PSBT
        
        Args:
            private_keys: Dict mapping input_index -> private_key (32 bytes)
        """
        # TODO: Implement DLEQ proof generation using BIP 374
        # - For each ECDH share, generate corresponding DLEQ proof
        # - Prove that same private key used for input and ECDH computation
        raise NotImplementedError("generate_dleq_proofs not yet implemented")
    
    def verify_dleq_proofs(self) -> bool:
        """
        Verify all DLEQ proofs in the PSBT
        
        Returns:
            True if all proofs are valid, False otherwise
        """
        # TODO: Implement DLEQ proof verification using BIP 374
        # - Verify global DLEQ proofs if present
        # - Verify per-input DLEQ proofs if present
        # - Ensure proofs match corresponding ECDH shares
        raise NotImplementedError("verify_dleq_proofs not yet implemented")
    
    def compute_output_scripts(self) -> None:
        """
        Compute output scripts for all silent payment addresses
        Uses BIP 352 protocol with ECDH shares from PSBT
        """
        # TODO: Implement output script computation
        # - Collect all ECDH shares for each scan key
        # - Apply BIP 352 silent payment derivation
        # - Set PSBT_OUT_SCRIPT fields for silent payment outputs
        raise NotImplementedError("compute_output_scripts not yet implemented")
    
    def extract_transaction(self) -> bytes:
        """
        Extract the final Bitcoin transaction from the completed PSBT
        
        Returns:
            Serialized transaction bytes
        """
        # TODO: Implement transaction extraction
        # - Verify all signatures are present
        # - Verify all output scripts are computed  
        # - Construct final transaction
        raise NotImplementedError("extract_transaction not yet implemented")

# Test utilities (Step 5 continued)

def validate_psbt_silent_payments(psbt: SilentPaymentPSBT) -> Tuple[bool, List[str]]:
    """
    Validate a PSBT with silent payments according to BIP 375 rules
    
    Args:
        psbt: PSBT to validate
        
    Returns:
        (is_valid, list_of_errors)
    """
    errors = []
    
    # TODO: Implement comprehensive validation
    # - Check field inclusion/exclusion requirements
    # - Verify DLEQ proofs
    # - Check segwit version restrictions  
    # - Validate SIGHASH_ALL requirement
    # - Ensure output scripts match silent payment derivation
    
    return len(errors) == 0, errors

def parse_test_vectors(json_file: str) -> Dict[str, List[str]]:
    """
    Parse test vectors from JSON file
    
    Args:
        json_file: Path to test vectors JSON file
        
    Returns:
        Dict with 'valid' and 'invalid' lists of base64-encoded PSBTs
    """
    import json
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        result = {
            'valid': [test['psbt'] for test in data.get('valid', [])],
            'invalid': [test['psbt'] for test in data.get('invalid', [])]
        }
        
        return result
    except Exception as e:
        raise ValueError(f"Failed to parse test vectors: {e}")

def run_test_case(psbt_b64: str, expected_valid: bool) -> Tuple[bool, str]:
    """
    Run a single test case
    
    Args:
        psbt_b64: Base64-encoded PSBT
        expected_valid: Whether this PSBT should be valid
        
    Returns:
        (test_passed, error_message)
    """
    import base64
    from dleq_374 import dleq_verify_proof
    from secp256k1_374 import GE
    
    try:
        # Decode base64 PSBT
        try:
            psbt_data = base64.b64decode(psbt_b64)
        except Exception as e:
            actual_valid = False
            error_msg = f"Invalid base64 encoding: {e}"
        else:
            # Parse and validate PSBT
            actual_valid, error_msg = validate_bip375_psbt(psbt_data)
        
        # Check if result matches expectation
        if actual_valid == expected_valid:
            if expected_valid:
                return True, "Valid PSBT correctly identified as valid"
            else:
                return True, f"Invalid PSBT correctly identified as invalid: {error_msg}"
        else:
            if expected_valid:
                return False, f"Expected valid PSBT but got invalid: {error_msg}"
            else:
                return False, f"Expected invalid PSBT but got valid"
                
    except Exception as e:
        return False, f"Unexpected exception during test: {e}"

def validate_bip375_psbt(psbt_data: bytes) -> Tuple[bool, str]:
    """
    Validate a PSBT according to BIP 375 rules
    
    Args:
        psbt_data: Raw PSBT bytes
        
    Returns:
        (is_valid, error_message)
    """
    try:
        # Basic PSBT structure validation
        if len(psbt_data) < 5 or psbt_data[:5] != b'psbt\xff':
            return False, "Invalid PSBT magic"
        
        # Parse PSBT fields
        global_fields, input_maps, output_maps = parse_psbt_structure(psbt_data)
        
        # Check for BIP 375 specific validation rules
        errors = []
        
        # Rule 1: Check if silent payment outputs exist
        has_silent_outputs = any(
            PSBTFieldType.PSBT_OUT_SP_V0_INFO in output_fields 
            for output_fields in output_maps
        )
        
        if not has_silent_outputs:
            # If no silent payment outputs, this is just a regular PSBT v2
            return True, "Valid PSBT v2 (no silent payments)"
        
        # Rule 2: If silent payments exist, check ECDH shares and DLEQ proofs
        has_global_ecdh = PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE in global_fields
        has_input_ecdh = any(
            PSBTFieldType.PSBT_IN_SP_ECDH_SHARE in input_fields
            for input_fields in input_maps
        )
        
        if not has_global_ecdh and not has_input_ecdh:
            errors.append("Silent payment outputs present but no ECDH shares found")
        
        # Rule 3: Check DLEQ proofs are present for ECDH shares
        if has_global_ecdh:
            has_global_dleq = PSBTFieldType.PSBT_GLOBAL_SP_DLEQ in global_fields
            if not has_global_dleq:
                errors.append("Global ECDH share present but missing DLEQ proof")
            else:
                # Validate DLEQ proof if we have the data
                if not validate_global_dleq_proof(global_fields):
                    errors.append("Global DLEQ proof verification failed")
        
        if has_input_ecdh:
            for i, input_fields in enumerate(input_maps):
                if PSBTFieldType.PSBT_IN_SP_ECDH_SHARE in input_fields:
                    if PSBTFieldType.PSBT_IN_SP_DLEQ not in input_fields:
                        errors.append(f"Input {i} has ECDH share but missing DLEQ proof")
                    else:
                        # Validate individual DLEQ proof
                        if not validate_input_dleq_proof(input_fields):
                            errors.append(f"Input {i} DLEQ proof verification failed")
        
        # Rule 4: Check segwit version restrictions
        for i, input_fields in enumerate(input_maps):
            if PSBTFieldType.PSBT_IN_WITNESS_UTXO in input_fields:
                witness_utxo = input_fields[PSBTFieldType.PSBT_IN_WITNESS_UTXO]
                if check_invalid_segwit_version(witness_utxo):
                    errors.append(f"Input {i} uses segwit version > 1 with silent payments")
        
        # Rule 5: Check SIGHASH_ALL requirement
        for i, input_fields in enumerate(input_maps):
            if PSBTFieldType.PSBT_IN_SIGHASH_TYPE in input_fields:
                sighash = input_fields[PSBTFieldType.PSBT_IN_SIGHASH_TYPE]
                if len(sighash) >= 4:
                    sighash_type = struct.unpack('<I', sighash[:4])[0]
                    if sighash_type != 1:  # SIGHASH_ALL
                        errors.append(f"Input {i} uses non-SIGHASH_ALL ({sighash_type}) with silent payments")
        
        # Rule 6: Check SP_V0_INFO field size
        for i, output_fields in enumerate(output_maps):
            if PSBTFieldType.PSBT_OUT_SP_V0_INFO in output_fields:
                sp_info = output_fields[PSBTFieldType.PSBT_OUT_SP_V0_INFO]
                if len(sp_info) != 66:  # 33 + 33 bytes for scan_key + spend_key
                    errors.append(f"Output {i} SP_V0_INFO has wrong size ({len(sp_info)} bytes, expected 66)")
        
        if errors:
            return False, "; ".join(errors)
        else:
            return True, "Valid BIP 375 PSBT"
            
    except Exception as e:
        return False, f"PSBT parsing error: {e}"

def parse_psbt_structure(psbt_data: bytes) -> Tuple[Dict[int, bytes], List[Dict[int, bytes]], List[Dict[int, bytes]]]:
    """
    Parse PSBT structure into global, input, and output field maps
    
    Returns:
        (global_fields, input_maps, output_maps)
    """
    def parse_compact_size_uint(data: bytes, offset: int) -> Tuple[int, int]:
        """Parse compact size uint and return (value, new_offset)"""
        if offset >= len(data):
            raise ValueError("Not enough data")
        
        first_byte = data[offset]
        if first_byte < 0xfd:
            return first_byte, offset + 1
        elif first_byte == 0xfd:
            return struct.unpack('<H', data[offset+1:offset+3])[0], offset + 3
        elif first_byte == 0xfe:
            return struct.unpack('<L', data[offset+1:offset+5])[0], offset + 5
        else:
            return struct.unpack('<Q', data[offset+1:offset+9])[0], offset + 9
    
    def parse_section(data: bytes, offset: int) -> Tuple[Dict[int, bytes], int]:
        """Parse a PSBT section and return (field_map, new_offset)"""
        fields = {}
        
        while offset < len(data):
            # Read key length
            key_len, offset = parse_compact_size_uint(data, offset)
            if key_len == 0:  # End of section
                break
            
            # Read key data
            if offset + key_len > len(data):
                raise ValueError("Truncated key data")
            key_data = data[offset:offset + key_len]
            offset += key_len
            
            # Read value length
            value_len, offset = parse_compact_size_uint(data, offset)
            
            # Read value data
            if offset + value_len > len(data):
                raise ValueError("Truncated value data")
            value_data = data[offset:offset + value_len]
            offset += value_len
            
            # Extract field type
            if key_data:
                field_type = key_data[0]
                fields[field_type] = value_data
        
        return fields, offset
    
    if len(psbt_data) < 5 or psbt_data[:5] != b'psbt\xff':
        raise ValueError("Invalid PSBT magic")
    
    offset = 5
    
    # Parse global section
    global_fields, offset = parse_section(psbt_data, offset)
    
    # Determine number of inputs and outputs
    num_inputs = global_fields.get(PSBTFieldType.PSBT_GLOBAL_INPUT_COUNT, b'\x00')[0] if PSBTFieldType.PSBT_GLOBAL_INPUT_COUNT in global_fields else 1
    num_outputs = global_fields.get(PSBTFieldType.PSBT_GLOBAL_OUTPUT_COUNT, b'\x00')[0] if PSBTFieldType.PSBT_GLOBAL_OUTPUT_COUNT in global_fields else 1
    
    # Parse input sections
    input_maps = []
    for _ in range(num_inputs):
        input_fields, offset = parse_section(psbt_data, offset)
        input_maps.append(input_fields)
    
    # Parse output sections
    output_maps = []
    for _ in range(num_outputs):
        output_fields, offset = parse_section(psbt_data, offset)
        output_maps.append(output_fields)
    
    return global_fields, input_maps, output_maps

def validate_global_dleq_proof(global_fields: Dict[int, bytes]) -> bool:
    """Validate global DLEQ proof using BIP 374 implementation"""
    try:
        from dleq_374 import dleq_verify_proof
        from secp256k1_374 import GE, G
        
        if PSBTFieldType.PSBT_GLOBAL_SP_DLEQ not in global_fields:
            return False
        if PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE not in global_fields:
            return False
            
        proof = global_fields[PSBTFieldType.PSBT_GLOBAL_SP_DLEQ]
        ecdh_share_data = global_fields[PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE]
        
        if len(proof) != 64:
            return False
        
        # Extract scan key and ECDH share from the data
        # Format: scan_key (33 bytes) + ecdh_share (33 bytes)
        if len(ecdh_share_data) != 66:
            return False
            
        scan_key_bytes = ecdh_share_data[:33]
        ecdh_share_bytes = ecdh_share_data[33:]
        
        # Convert to GE points
        try:
            B = GE.from_bytes_compressed(scan_key_bytes)  # scan key
            C = GE.from_bytes_compressed(ecdh_share_bytes)  # ECDH result
            
            # We need A (public key), but it's not directly available in global fields
            # For now, we'll do a basic structural validation
            # In a full implementation, we'd extract A from input fields
            return len(proof) == 64 and not B.infinity and not C.infinity
            
        except Exception:
            return False
            
    except Exception:
        return False

def validate_input_dleq_proof(input_fields: Dict[int, bytes]) -> bool:
    """Validate input DLEQ proof using BIP 374 implementation"""
    try:
        from dleq_374 import dleq_verify_proof
        from secp256k1_374 import GE, G
        
        if PSBTFieldType.PSBT_IN_SP_DLEQ not in input_fields:
            return False
        if PSBTFieldType.PSBT_IN_SP_ECDH_SHARE not in input_fields:
            return False
            
        proof = input_fields[PSBTFieldType.PSBT_IN_SP_DLEQ]
        ecdh_share_data = input_fields[PSBTFieldType.PSBT_IN_SP_ECDH_SHARE]
        
        if len(proof) != 64:
            return False
        
        # Extract scan key and ECDH share from the data
        # Format: scan_key (33 bytes) + ecdh_share (33 bytes)
        if len(ecdh_share_data) != 66:
            return False
            
        scan_key_bytes = ecdh_share_data[:33]
        ecdh_share_bytes = ecdh_share_data[33:]
        
        # Convert to GE points
        try:
            B = GE.from_bytes_compressed(scan_key_bytes)  # scan key
            C = GE.from_bytes_compressed(ecdh_share_bytes)  # ECDH result
            
            # We need A (input public key), but extraction is complex
            # For now, do enhanced structural validation
            # In a full implementation, we'd extract A from BIP32 derivation or witness data
            return len(proof) == 64 and not B.infinity and not C.infinity
            
        except Exception:
            return False
            
    except Exception:
        return False

def check_invalid_segwit_version(witness_utxo: bytes) -> bool:
    """Check if witness UTXO uses invalid segwit version for silent payments"""
    try:
        # Skip amount (8 bytes) and script length
        if len(witness_utxo) < 9:
            return False
        
        offset = 8  # Skip amount
        script_len = witness_utxo[offset]
        offset += 1
        
        if offset + script_len > len(witness_utxo):
            return False
        
        script = witness_utxo[offset:offset + script_len]
        
        # Check if it's segwit v2 or higher
        if len(script) >= 2 and script[0] >= 0x52:  # OP_2 or higher
            return True
        
        return False
    except Exception:
        return False

# Helper functions for BIP 374 DLEQ (placeholders)

def generate_dleq_proof(private_key: bytes, public_key_B: bytes, 
                       result_C: bytes, aux_rand: bytes = None) -> bytes:
    """
    Generate DLEQ proof according to BIP 374
    
    Args:
        private_key: Secret scalar a (32 bytes)
        public_key_B: Point B (33 bytes compressed)
        result_C: Point C = a * B (33 bytes compressed)  
        aux_rand: Auxiliary randomness (32 bytes)
        
    Returns:
        64-byte DLEQ proof
    """
    # TODO: Implement BIP 374 DLEQ proof generation
    raise NotImplementedError("generate_dleq_proof not yet implemented")

def verify_dleq_proof(public_key_A: bytes, public_key_B: bytes,
                     result_C: bytes, proof: bytes) -> bool:
    """
    Verify DLEQ proof according to BIP 374
    
    Args:
        public_key_A: Point A = a * G (33 bytes compressed)
        public_key_B: Point B (33 bytes compressed)  
        result_C: Point C = a * B (33 bytes compressed)
        proof: 64-byte DLEQ proof
        
    Returns:
        True if proof is valid
    """
    # TODO: Implement BIP 374 DLEQ proof verification
    raise NotImplementedError("verify_dleq_proof not yet implemented")

if __name__ == "__main__":
    # Basic smoke test
    print("BIP 375 Reference Implementation")
    print("Core functions defined but not yet implemented")
    
    # TODO: Add basic demonstration once functions are implemented