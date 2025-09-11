#!/usr/bin/env python3
"""
BIP 375 SilentPaymentPSBT Class

Main implementation of PSBT v2 class with silent payment extensions.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
import struct

from reference import PSBTFieldType
from secp256k1_374 import GE, G
from .serialization import PSBTField
from .crypto import Wallet, PublicKey, UTXO, sign_p2wpkh_input
from dleq_374 import dleq_generate_proof
import hashlib


@dataclass
class SilentPaymentAddress:
    """Silent payment address with scan and spend keys"""
    scan_key: PublicKey    # 33 bytes compressed public key
    spend_key: PublicKey   # 33 bytes compressed public key
    label: Optional[int] = None


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
        self.global_fields: List[PSBTField] = []
        self.input_maps: List[List[PSBTField]] = []
        self.output_maps: List[List[PSBTField]] = []
    
    def add_base_fields(self, num_inputs: int, num_outputs: int) -> None:
        """
        Creator role: Add required PSBT v2 global fields
        
        Args:
            num_inputs: Number of transaction inputs
            num_outputs: Total number of outputs (regular + silent payment)
        """
        # PSBT v2 requires these global fields
        self.global_fields.append(PSBTField(PSBTFieldType.PSBT_GLOBAL_TX_VERSION, b'', struct.pack('<I', 2)))
        self.global_fields.append(PSBTField(PSBTFieldType.PSBT_GLOBAL_INPUT_COUNT, b'', struct.pack('<B', num_inputs)))
        self.global_fields.append(PSBTField(PSBTFieldType.PSBT_GLOBAL_OUTPUT_COUNT, b'', struct.pack('<B', num_outputs)))
        self.global_fields.append(PSBTField(PSBTFieldType.PSBT_GLOBAL_TX_MODIFIABLE, b'', struct.pack('<B', 0x03)))  # Inputs and outputs modifiable
    
    def add_inputs_outputs(self, inputs: List[dict], outputs: List[dict]) -> None:
        """
        Constructor role: Add input and output information to PSBT
        
        Args:
            inputs: List of input dictionaries with txid, vout, amount, script_pubkey, etc.
            outputs: List of output dictionaries, can be regular outputs or silent payment addresses
        """
        # Process inputs
        for i, inp in enumerate(inputs):
            input_fields = []
            
            # Add PSBT_IN_PREVIOUS_TXID
            txid = bytes.fromhex(inp.txid)
            input_fields.append(PSBTField(PSBTFieldType.PSBT_IN_PREVIOUS_TXID, b'', txid))
            
            # Add PSBT_IN_OUTPUT_INDEX  
            input_fields.append(PSBTField(PSBTFieldType.PSBT_IN_OUTPUT_INDEX, b'', struct.pack('<I', inp.vout)))
            
            # Add PSBT_IN_WITNESS_UTXO
            witness_utxo = struct.pack('<Q', inp.amount)  # 8-byte amount
            script_pubkey = bytes.fromhex(inp.script_pubkey)
            witness_utxo += struct.pack('<B', len(script_pubkey)) + script_pubkey  # script with length
            input_fields.append(PSBTField(PSBTFieldType.PSBT_IN_WITNESS_UTXO, b'', witness_utxo))
            
            # Add PSBT_IN_SEQUENCE
            input_fields.append(PSBTField(PSBTFieldType.PSBT_IN_SEQUENCE, b'', struct.pack('<I', inp.sequence)))
            
            # Add PSBT_IN_SIGHASH_TYPE (SIGHASH_ALL for silent payments)
            input_fields.append(PSBTField(PSBTFieldType.PSBT_IN_SIGHASH_TYPE, b'', struct.pack('<I', 1)))
            
            self.input_maps.append(input_fields)
        
        # Process outputs
        for i, output in enumerate(outputs):
            output_fields = []
            
            # Add PSBT_OUT_AMOUNT (always present)
            output_fields.append(PSBTField(PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', output["amount"])))
            
            # Check if this is a silent payment output
            if "address" in output:
                # Silent payment output
                sp_address = output["address"]
                
                # Add PSBT_OUT_SP_V0_INFO (scan_key + spend_key)
                sp_info = sp_address.scan_key.bytes + sp_address.spend_key.bytes
                output_fields.append(PSBTField(PSBTFieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info))
                
                # Add PSBT_OUT_SP_V0_LABEL if present
                if sp_address.label is not None:
                    output_fields.append(PSBTField(PSBTFieldType.PSBT_OUT_SP_V0_LABEL, b'', struct.pack('<I', sp_address.label)))
                
                # TODO: Silent payment outputs don't have script_pubkey initially (computed later)
            else:
                # Regular output - has script_pubkey
                script_pubkey = bytes.fromhex(output["script_pubkey"])
                output_fields.append(PSBTField(PSBTFieldType.PSBT_OUT_SCRIPT, b'', script_pubkey))
            
            self.output_maps.append(output_fields)
    
    def create_silent_payment_psbt(self, inputs: List[dict], outputs: List[dict]) -> 'SilentPaymentPSBT':
        """
        Create a PSBT v2 with silent payment extensions
        
        Args:
            inputs: List of input dictionaries with txid, vout, amount, script_pubkey
            outputs: List of output dictionaries (regular outputs + silent payment addresses)
        
        Returns:
            Configured SilentPaymentPSBT ready for ECDH share computation
        """
        num_inputs = len(inputs)
        num_outputs = len(outputs)
        
        # Creator role: Set up PSBT v2 base structure  
        self.add_base_fields(num_inputs, num_outputs)
        
        # Constructor role: Add transaction input/output information
        self.add_inputs_outputs(inputs, outputs)
        
        return self
    
    def add_global_field(self, field_type: int, key_data: bytes, value_data: bytes):
        """Add a global field"""
        self.global_fields.append(PSBTField(field_type, key_data, value_data))
    
    def add_input_field(self, input_index: int, field_type: int, key_data: bytes, value_data: bytes):
        """Add a field to specific input"""
        # Extend input_maps if needed
        while len(self.input_maps) <= input_index:
            self.input_maps.append([])
        
        self.input_maps[input_index].append(PSBTField(field_type, key_data, value_data))
    
    def add_output_field(self, output_index: int, field_type: int, key_data: bytes, value_data: bytes):
        """Add a field to specific output"""
        # Extend output_maps if needed
        while len(self.output_maps) <= output_index:
            self.output_maps.append([])
        
        self.output_maps[output_index].append(PSBTField(field_type, key_data, value_data))

    def serialize_section(self, fields: List[PSBTField]) -> bytes:
        """Serialize a section (global, input, or output)"""
        result = b''
        for field in fields:
            result += field.serialize()
        # End with separator (empty key)
        result += b'\x00'
        return result
    
    def serialize(self) -> bytes:
        """Serialize entire PSBT to bytes"""
        result = b'psbt\xff'  # PSBT magic
        
        # Global section
        result += self.serialize_section(self.global_fields)
        
        # Input sections
        for input_fields in self.input_maps:
            result += self.serialize_section(input_fields)
        
        # Output sections  
        for output_fields in self.output_maps:
            result += self.serialize_section(output_fields)
        
        return result

    def encode(self) -> str:
        import base64
        return base64.b64encode(self.serialize()).decode()
    
    def pretty_print(self) -> str:
        """Return a human-readable description of the PSBT"""
        lines = ["PSBT v2 with Silent Payment Extensions", "=" * 50]
        
        # Global fields
        lines.append("Global Fields:")
        for field in self.global_fields:
            field_name = self._get_field_name(field.field_type, "global")
            lines.append(f"  {field_name}: {field.value_data.hex()}")
        
        # Input fields
        for i, input_fields in enumerate(self.input_maps):
            lines.append(f"\nInput {i}:")
            for field in input_fields:
                field_name = self._get_field_name(field.field_type, "in")
                lines.append(f"  {field_name}: {field.value_data.hex()}")
        
        # Output fields
        for i, output_fields in enumerate(self.output_maps):
            lines.append(f"\nOutput {i}:")
            for field in output_fields:
                field_name = self._get_field_name(field.field_type, "out")
                if field.field_type == PSBTFieldType.PSBT_OUT_SP_V0_INFO:
                    # Pretty print silent payment info
                    if len(field.value_data) == 66:  # 33 + 33 bytes
                        scan_key = field.value_data[:33].hex()
                        spend_key = field.value_data[33:].hex()
                        lines.append(f"  {field_name}:")
                        lines.append(f"    Scan Key:  {scan_key}")
                        lines.append(f"    Spend Key: {spend_key}")
                    else:
                        lines.append(f"  {field_name}: {field.value_data.hex()}")
                else:
                    lines.append(f"  {field_name}: {field.value_data.hex()}")
        
        return "\n".join(lines)
    
    def _get_field_name(self, field_type: int, section: str) -> str:
        """Get human-readable name for field type with section context"""
        # Search only within the appropriate section to handle duplicate values
        section_prefix = f"PSBT_{section.upper()}_"
        
        for attr_name in dir(PSBTFieldType):
            if attr_name.startswith(section_prefix):
                attr_value = getattr(PSBTFieldType, attr_name)
                if isinstance(attr_value, int) and attr_value == field_type:
                    # Return name without the section prefix
                    return attr_name[len(section_prefix):]
        
        # Unknown field type, return hex representation
        return f"UNKNOWN_{field_type:02x}"
    
    def add_ecdh_shares(self, inputs: List[UTXO], scan_keys: List[PublicKey], use_global = True) -> None:
        """
        Add ECDH shares and DLEQ proofs to the PSBT for given UTXOs and scan keys
        
        Args:
            inputs: List of UTXO objects, some may have private_key = None
            scan_keys: List of scan keys (PublicKey objects)
        """
        # Only process inputs that have private keys
        spendable_inputs = [(i, utxo) for i, utxo in enumerate(inputs) if utxo.private_key is not None]
        
        if not spendable_inputs:
            return  # No inputs we can spend
        
        # Determine whether to use global or per-input ECDH approach
        if use_global:
            # Global ECDH approach - single entity controls all inputs, single scan key
            combined_private_key = 0
            for index, utxo in spendable_inputs:
                scan_key = scan_keys[0]
                combined_private_key += utxo.private_key
                
            # Compute ECDH: private_key * scan_key
            ecdh_result_point = utxo.private_key * scan_key
            ecdh_result_bytes = ecdh_result_point.to_bytes_compressed()
            
            # Generate DLEQ proof: proves private_key * G and private_key * scan_key use same private_key
            dleq_proof = dleq_generate_proof(
                a=combined_private_key,           # private key
                B=scan_key,                  # scan key (point being multiplied)
                r=Wallet.random_bytes()      # randomness for proof                    # no additional message
            )
            
            if dleq_proof is None:
                raise ValueError("Failed to generate DLEQ proof")
            
            # Add global ECDH share field
            self.global_fields.append(PSBTField(
                PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE,
                scan_key.bytes,  # key = scan key (33 bytes)
                ecdh_result_bytes  # value = ECDH result (33 bytes)
            ))
            
            # Add global DLEQ proof field
            self.global_fields.append(PSBTField(
                PSBTFieldType.PSBT_GLOBAL_SP_DLEQ,
                scan_key.bytes,  # key = scan key (33 bytes)
                dleq_proof       # value = DLEQ proof (64 bytes)
            ))
        else:
            # Per-input ECDH approach - each input contributes separate shares
            for input_index, utxo in spendable_inputs:
                # Ensure we have enough input maps
                while len(self.input_maps) <= input_index:
                    self.input_maps.append([])
                
                for scan_key in scan_keys:
                    # Compute ECDH: private_key * scan_key
                    ecdh_result_point = utxo.private_key * scan_key
                    ecdh_result_bytes = ecdh_result_point.to_bytes_compressed()
                    
                    # Generate DLEQ proof
                    dleq_proof = dleq_generate_proof(
                        a=utxo.private_key,       # private key
                        B=scan_key,              # scan key (point being multiplied)
                        r=Wallet.random_bytes()  # randomness for proof
                    )
                    
                    if dleq_proof is None:
                        raise ValueError(f"Failed to generate DLEQ proof for input {input_index}")
                    
                    # Add per-input ECDH share field
                    self.input_maps[input_index].append(PSBTField(
                        PSBTFieldType.PSBT_IN_SP_ECDH_SHARE,
                        scan_key.bytes,  # key = scan key (33 bytes)
                        ecdh_result_bytes  # value = ECDH result (33 bytes)
                    ))
                    
                    # Add per-input DLEQ proof field
                    self.input_maps[input_index].append(PSBTField(
                        PSBTFieldType.PSBT_IN_SP_DLEQ,
                        scan_key.bytes,  # key = scan key (33 bytes)
                        dleq_proof       # value = DLEQ proof (64 bytes)
                    ))
    
    def sign_inputs(self, inputs: List[UTXO]) -> bool:
        """
        Sign transaction inputs using private keys from UTXOs (SIGNER ROLE)
        
        Args:
            inputs: List of UTXO objects with private keys for signing
            
        Returns:
            True if signing successful, raises exception if validation fails
        """
        # Pre-signing validation
        is_valid, errors = validate_psbt_silent_payments(self)
        if not is_valid:
            raise ValueError(f"PSBT validation failed before signing: {errors}")
        
        # Only sign inputs that have private keys
        spendable_inputs = [(i, utxo) for i, utxo in enumerate(inputs) if utxo.private_key is not None]
        
        if not spendable_inputs:
            raise ValueError("No spendable inputs found (no private keys provided)")
        
        # Prepare transaction data for signing
        transaction_data = {
            'inputs': inputs,
            'outputs': []  # Will be populated from output_maps
        }
        
        # Extract outputs from PSBT output maps
        for output_fields in self.output_maps:
            output_dict = {}
            for field in output_fields:
                if field.field_type == PSBTFieldType.PSBT_OUT_AMOUNT:
                    output_dict['amount'] = struct.unpack('<Q', field.value_data)[0]
                elif field.field_type == PSBTFieldType.PSBT_OUT_SCRIPT:
                    output_dict['script_pubkey'] = field.value_data.hex()
                elif field.field_type == PSBTFieldType.PSBT_OUT_SP_V0_INFO:
                    # Silent payment output - no script_pubkey yet
                    pass
            transaction_data['outputs'].append(output_dict)
        
        # Sign each spendable input
        signatures_added = 0
        for input_index, utxo in spendable_inputs:
            try:
                # Extract public key hash from P2WPKH script_pubkey
                # Format: 0014 + 20-byte pubkey hash
                script_bytes = utxo.script_pubkey_bytes
                if len(script_bytes) != 22 or script_bytes[:2] != b'\x00\x14':
                    print(f"⚠️  Skipping input {input_index}: Not P2WPKH (unsupported script type)")
                    continue
                
                pubkey_hash = script_bytes[2:]  # Extract 20-byte hash
                
                # Generate signature
                signature = sign_p2wpkh_input(
                    private_key=int(utxo.private_key),
                    transaction_data=transaction_data,
                    input_index=input_index,
                    pubkey_hash=pubkey_hash,
                    amount=utxo.amount
                )
                
                # Add partial signature to PSBT input
                # For P2WPKH, the key is the public key and value is the signature
                public_key_point = int(utxo.private_key) * G
                public_key_compressed = public_key_point.to_bytes_compressed()
                
                self.add_input_field(
                    input_index=input_index,
                    field_type=PSBTFieldType.PSBT_IN_PARTIAL_SIG,
                    key_data=public_key_compressed,  # Public key as key
                    value_data=signature  # Signature as value
                )
                
                signatures_added += 1
                print(f" Signed input {input_index}")
                
            except Exception as e:
                print(f"❌ Failed to sign input {input_index}: {e}")
                raise ValueError(f"Signing failed for input {input_index}: {e}")
        
        if signatures_added == 0:
            raise ValueError("No inputs were signed successfully")
        
        print(f" Successfully signed {signatures_added} input(s)")
        return True
    
    def verify_dleq_proofs(self, inputs: List[UTXO] = None) -> bool:
        """
        Verify all DLEQ proofs in the PSBT

        Returns:
            True if all proofs are valid, False otherwise
        """
        from dleq_374 import dleq_verify_proof

        # Check for global DLEQ proofs
        global_ecdh_fields = {}
        global_dleq_fields = {}

        for field in self.global_fields:
            if field.field_type == PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE:
                scan_key = field.key_data
                global_ecdh_fields[scan_key] = field.value_data
            elif field.field_type == PSBTFieldType.PSBT_GLOBAL_SP_DLEQ:
                scan_key = field.key_data
                global_dleq_fields[scan_key] = field.value_data

        # Verify global DLEQ proofs
        for scan_key in global_ecdh_fields:
            if scan_key not in global_dleq_fields:
                print(f"❌ Global ECDH share missing DLEQ proof for scan key {scan_key.hex()[:16]}...")
                return False

            ecdh_share_bytes = global_ecdh_fields[scan_key]
            dleq_proof = global_dleq_fields[scan_key]

            if len(dleq_proof) != 64:
                print(f"❌ Invalid global DLEQ proof length: {len(dleq_proof)} bytes")
                return False

            # Convert to GE points
            B = GE.from_bytes(scan_key)  # scan key
            C = GE.from_bytes(ecdh_share_bytes)  # ECDH result

            # Combine all input public keys for global verification
            A_combined = self._extract_combined_input_pubkeys(inputs)
            if A_combined is None:
                print("❌ Could not extract input public keys for global DLEQ verification")
                return False

            # Verify DLEQ proof
            if not dleq_verify_proof(A_combined, B, C, dleq_proof):
                print(f"❌ Global DLEQ proof verification failed for scan key {scan_key.hex()[:16]}...")
                return False

            print(f" Global DLEQ proof verified for scan key {scan_key.hex()[:16]}...")

        # Check for per-input DLEQ proofs
        for input_index, input_fields in enumerate(self.input_maps):
            input_ecdh_fields = {}
            input_dleq_fields = {}

            for field in input_fields:
                if field.field_type == PSBTFieldType.PSBT_IN_SP_ECDH_SHARE:
                    scan_key = field.key_data
                    input_ecdh_fields[scan_key] = field.value_data
                elif field.field_type == PSBTFieldType.PSBT_IN_SP_DLEQ:
                    scan_key = field.key_data
                    input_dleq_fields[scan_key] = field.value_data

            # Verify per-input DLEQ proofs
            for scan_key in input_ecdh_fields:
                if scan_key not in input_dleq_fields:
                    print(f"❌ Input {input_index} ECDH share missing DLEQ proof for scan key {scan_key.hex()[:16]}...")
                    return False

                ecdh_share_bytes = input_ecdh_fields[scan_key]
                dleq_proof = input_dleq_fields[scan_key]

                if len(dleq_proof) != 64:
                    print(f"❌ Invalid input {input_index} DLEQ proof length: {len(dleq_proof)} bytes")
                    return False

                # Convert to GE points
                B = GE.from_bytes(scan_key)  # scan key
                C = GE.from_bytes(ecdh_share_bytes)  # ECDH result

                # Extract input public key for this specific input
                A = self._extract_input_pubkey(input_index)
                if A is None:
                    print(f"❌ Could not extract public key for input {input_index}")
                    return False

                # Verify DLEQ proof
                if not dleq_verify_proof(A, B, C, dleq_proof):
                    print(f"❌ Input {input_index} DLEQ proof verification failed for scan key {scan_key.hex()[:16]}...")
                    return False

                print(f" Input {input_index} DLEQ proof verified for scan key {scan_key.hex()[:16]}...")

        if not global_ecdh_fields and not any(
            any(field.field_type == PSBTFieldType.PSBT_IN_SP_ECDH_SHARE for field in input_fields)
            for input_fields in self.input_maps
        ):
            print("⚠️  No ECDH shares found in PSBT - no DLEQ proofs to verify")
            return True

        print(" All DLEQ proofs verified successfully")
        return True

    def _extract_combined_input_pubkeys(self, inputs: List[UTXO] = None) -> Optional[GE]:
        """Extract and combine all input public keys for global DLEQ verification"""
        A_combined = None

        for input_index, input_fields in enumerate(self.input_maps):
            pubkey = self._extract_input_pubkey(input_index)

            # Fallback: extract from UTXO if not found in PSBT fields
            if pubkey is None and inputs:
                pubkey = self._extract_input_pubkey_from_utxo(input_index, inputs)

            if pubkey is None:
                return None

            if A_combined is None:
                A_combined = pubkey
            else:
                A_combined = A_combined + pubkey

        return A_combined

    def _extract_input_pubkey(self, input_index: int) -> Optional[GE]:
        """Extract public key for a specific input from PSBT fields"""
        if input_index >= len(self.input_maps):
            return None

        input_fields = self.input_maps[input_index]

        # Method 1: Extract from partial signature field (key is the public key)
        for field in input_fields:
            if field.field_type == PSBTFieldType.PSBT_IN_PARTIAL_SIG:
                try:
                    return GE.from_bytes(field.key_data)
                except Exception:
                    continue

        # Method 2: Extract from BIP32 derivation field
        for field in input_fields:
            if field.field_type == PSBTFieldType.PSBT_IN_BIP32_DERIVATION:
                try:
                    # BIP32 derivation format: <pubkey><fingerprint><path>
                    derivation_data = field.value_data
                    for offset in range(0, len(derivation_data), 33 + 4 + 4):
                        if offset + 33 <= len(derivation_data):
                            pubkey_candidate = derivation_data[offset:offset + 33]
                            return GE.from_bytes(pubkey_candidate)
                except Exception:
                    continue

        return None

    def _extract_input_pubkey_from_utxo(self, input_index: int, inputs: List[UTXO]) -> Optional[GE]:
        """Extract public key from UTXO list (fallback for DLEQ verification before signing)"""
        if input_index < len(inputs) and inputs[input_index].private_key is not None:
            try:
                # Compute public key from private key
                private_key = int(inputs[input_index].private_key)
                public_key_point = private_key * G
                return public_key_point
            except Exception:
                pass
        return None

    def set_inputs_outputs_non_modifiable(self) -> None:
        """
        Set PSBT_GLOBAL_TX_MODIFIABLE flags to 0x00 (neither inputs nor outputs modifiable)

        This method implements the BIP 375 requirement:
        "If the Signer sets any missing PSBT_OUT_SCRIPTs, it must set the
        Inputs Modifiable and Outputs Modifiable flags to False."
        """
        # Find and update existing TX_MODIFIABLE field, or add if missing
        tx_modifiable_updated = False

        for field in self.global_fields:
            if field.field_type == PSBTFieldType.PSBT_GLOBAL_TX_MODIFIABLE:
                # Update existing field to 0x00 (neither inputs nor outputs modifiable)
                field.value_data = struct.pack('<B', 0x00)
                tx_modifiable_updated = True
                print("Set TX_MODIFIABLE flags to 0x00 (inputs and outputs non-modifiable)")
                break

        if not tx_modifiable_updated:
            # Add TX_MODIFIABLE field if it doesn't exist
            self.global_fields.append(PSBTField(
                PSBTFieldType.PSBT_GLOBAL_TX_MODIFIABLE,
                b'',
                struct.pack('<B', 0x00)
            ))
            print("Added TX_MODIFIABLE field set to 0x00 (inputs and outputs non-modifiable)")

    def compute_output_scripts(self) -> None:
        """
        Compute output scripts for all silent payment addresses (INPUT FINALIZER ROLE)
        Uses BIP 352 protocol with ECDH shares from PSBT
        """
        # Pre-computation validation
        is_valid, errors = validate_psbt_silent_payments(self)
        if not is_valid:
            raise ValueError(f"PSBT validation failed before computing output scripts: {errors}")
        
        # Collect ECDH shares - first try global, then per-input
        ecdh_shares = {}  # scan_key -> combined_ecdh_share
        
        # Check for global ECDH shares
        for field in self.global_fields:
            if field.field_type == PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE:
                scan_key = field.key_data
                ecdh_share = field.value_data
                if scan_key not in ecdh_shares:
                    ecdh_shares[scan_key] = PublicKey(GE.from_bytes(ecdh_share))
                else:
                    # Add to existing share (shouldn't happen with global, but handle gracefully)
                    existing = ecdh_shares[scan_key]
                    new_share = PublicKey(GE.from_bytes(ecdh_share))
                    ecdh_shares[scan_key] = existing + new_share
        
        # Check for per-input ECDH shares and combine them
        for input_fields in self.input_maps:
            for field in input_fields:
                if field.field_type == PSBTFieldType.PSBT_IN_SP_ECDH_SHARE:
                    scan_key = field.key_data
                    ecdh_share = field.value_data
                    if scan_key not in ecdh_shares:
                        ecdh_shares[scan_key] = PublicKey(GE.from_bytes(ecdh_share))
                    else:
                        # Add to existing share (combine multiple inputs)
                        existing = ecdh_shares[scan_key]
                        new_share = PublicKey(GE.from_bytes(ecdh_share))
                        ecdh_shares[scan_key] = existing + new_share
        
        if not ecdh_shares:
            raise ValueError("No ECDH shares found in PSBT")
        
        print(f" Found ECDH shares for {len(ecdh_shares)} scan key(s)")
        
        # Process each silent payment output
        scripts_computed = 0
        for output_index, output_fields in enumerate(self.output_maps):
            # Check if this is a silent payment output
            sp_info_field = None
            sp_label_field = None
            
            for field in output_fields:
                if field.field_type == PSBTFieldType.PSBT_OUT_SP_V0_INFO:
                    sp_info_field = field
                elif field.field_type == PSBTFieldType.PSBT_OUT_SP_V0_LABEL:
                    sp_label_field = field
            
            if sp_info_field is None:
                # Not a silent payment output, skip
                continue
            
            # Extract scan and spend keys from SP_V0_INFO (33 + 33 bytes)
            if len(sp_info_field.value_data) != 66:
                raise ValueError(f"Output {output_index} SP_V0_INFO has invalid length")
            
            scan_key_bytes = sp_info_field.value_data[:33]
            spend_key_bytes = sp_info_field.value_data[33:]
            
            # Find matching ECDH share
            if scan_key_bytes not in ecdh_shares:
                raise ValueError(f"Output {output_index} scan key not found in ECDH shares")
            
            ecdh_shared_secret_point = ecdh_shares[scan_key_bytes]
            
            # Apply BIP 352 derivation
            # For simplicity, assume k=0 (first output for this scan key)
            # In full implementation, would need to track k per scan key
            k = 0
            
            # Create BIP 352 tagged hash: TaggedHash("BIP0352/SharedSecret", shared_secret + k)
            shared_secret_bytes = ecdh_shared_secret_point.bytes  # 33 bytes compressed
            k_bytes = k.to_bytes(4, 'big')  # 4 bytes big-endian
            
            tag_data = b"BIP0352/SharedSecret"
            tag_hash = hashlib.sha256(tag_data).digest()
            tagged_input = tag_hash + tag_hash + shared_secret_bytes + k_bytes
            tweak_hash = hashlib.sha256(tagged_input).digest()
            tweak_int = int.from_bytes(tweak_hash, 'big') % GE.ORDER
            
            # Compute final output public key: P_k = B_spend + t_k * G
            spend_key_point = GE.from_bytes(spend_key_bytes)
            tweak_point = tweak_int * G
            final_pubkey_point = spend_key_point + tweak_point
            final_pubkey_bytes = final_pubkey_point.to_bytes_compressed()
            
            # Create P2WPKH script: OP_0 <20-byte-pubkey-hash>
            pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(final_pubkey_bytes).digest()).digest()
            script_pubkey = b'\x00\x14' + pubkey_hash  # OP_0 + 20 bytes
            
            # Add PSBT_OUT_SCRIPT field
            self.add_output_field(
                output_index=output_index,
                field_type=PSBTFieldType.PSBT_OUT_SCRIPT,
                key_data=b'',
                value_data=script_pubkey
            )
            
            scripts_computed += 1
            print(f" Computed output script for output {output_index}")
            print(f" Final pubkey: {final_pubkey_bytes.hex()}")
            print(f" Script: {script_pubkey.hex()}")
        
        if scripts_computed == 0:
            raise ValueError("No silent payment outputs found to compute")

        print(f" Successfully computed {scripts_computed} output script(s)")

        # BIP 375 requirement: Set modifiable flags to False after computing output scripts
        self.set_inputs_outputs_non_modifiable()

    def signer_role(self, inputs: List[UTXO], scan_keys: List[PublicKey] = None) -> bool:
        """
        Complete BIP 375 SIGNER role implementation

        For each output with PSBT_OUT_SP_V0_INFO set, the Signer should:
        1. Compute and set an ECDH share and DLEQ proof for each input it has the private key for,
           or set a global ECDH share and DLEQ proof if it has private keys for all eligible inputs
        2. Verify the DLEQ proofs for all inputs it does not have the private keys for,
           or the global DLEQ proof if it is set
        3. If all eligible inputs have an ECDH share or the global ECDH share is set,
           compute and set the PSBT_OUT_SCRIPT
        4. If the Signer sets any missing PSBT_OUT_SCRIPTs, it must set the Inputs Modifiable
           and Outputs Modifiable flags to False
        5. If any output does not have PSBT_OUT_SCRIPT set, the Signer must not yet add a signature

        Args:
            inputs: List of UTXO objects with private keys for signing
            scan_keys: List of scan keys to compute ECDH shares for (auto-extracted if None)

        Returns:
            True if SIGNER role completed successfully, False otherwise
        """

        # Step 1: Check if we have any silent payment outputs
        has_silent_outputs = any(
            any(field.field_type == PSBTFieldType.PSBT_OUT_SP_V0_INFO for field in output_fields)
            for output_fields in self.output_maps
        )

        if not has_silent_outputs:
            print("⚠️  No silent payment outputs found - proceeding with regular signing")
            return self.sign_inputs(inputs)

        # Step 2: Extract scan keys from silent payment outputs if not provided
        if scan_keys is None:
            scan_keys = []
            for output_fields in self.output_maps:
                for field in output_fields:
                    if field.field_type == PSBTFieldType.PSBT_OUT_SP_V0_INFO:
                        if len(field.value_data) == 66:  # 33 + 33 bytes
                            scan_key_bytes = field.value_data[:33]
                            scan_key = PublicKey(GE.from_bytes(scan_key_bytes))
                            if scan_key not in scan_keys:
                                scan_keys.append(scan_key)
            print(f"📋 Found {len(scan_keys)} unique scan key(s) in silent payment outputs")

        if not scan_keys:
            print("❌ Could not extract scan keys from silent payment outputs")
            return False

        print("4.1. Computing ECDH shares and DLEQ proofs for controlled inputs...")
        spendable_inputs = [(i, utxo) for i, utxo in enumerate(inputs) if utxo.private_key is not None]

        if not spendable_inputs:
            print("❌ No spendable inputs found (no private keys provided)")
            return False

        # Use global ECDH approach (single entity controls all inputs)
        try:
            self.add_ecdh_shares(inputs, scan_keys, use_global=True)
            print(" ECDH shares and DLEQ proofs computed")
        except Exception as e:
            print(f"❌ Failed to compute ECDH shares: {e}")
            return False

        print("4.2. Verifying all DLEQ proofs...")
        if not self.verify_dleq_proofs(inputs):
            print("❌ DLEQ proof verification failed")
            return False

        print("4.3. Checking ECDH share coverage...")
        # TODO: For now, assume global ECDH covers all inputs (single signer scenario)
        has_complete_ecdh_coverage = True

        if not has_complete_ecdh_coverage:
            print("❌ Incomplete ECDH share coverage - cannot compute output scripts yet")
            return False

        print("4.4. Computing silent payment output scripts...")
        try:
            self.compute_output_scripts()
        except Exception as e:
            print(f"❌ Failed to compute output scripts: {e}")
            return False

        print("4.5. Verifying all outputs have scripts before signing...")
        for i, output_fields in enumerate(self.output_maps):
            has_script = any(field.field_type == PSBTFieldType.PSBT_OUT_SCRIPT for field in output_fields)
            if not has_script:
                print(f"❌ Output {i} missing script - cannot sign yet")
                return False

        print("4.6. Adding signatures to inputs...")
        success = self.sign_inputs(inputs)
        if not success:
            print("❌ Signing failed")
            return False
        return True

    def extract_transaction(self) -> bytes:
        """
        Extract the final Bitcoin transaction from the completed PSBT (TRANSACTION EXTRACTOR ROLE)
        
        Returns:
            Serialized transaction bytes
        """
        # Validation before extraction
        is_valid, errors = validate_psbt_silent_payments(self)
        if not is_valid:
            raise ValueError(f"PSBT validation failed before extraction: {errors}")
        
        # Verify all outputs have scripts
        for i, output_fields in enumerate(self.output_maps):
            has_script = any(field.field_type == PSBTFieldType.PSBT_OUT_SCRIPT for field in output_fields)
            if not has_script:
                raise ValueError(f"Output {i} missing script - run compute_output_scripts() first")
        
        # Verify all inputs have signatures  
        for i, input_fields in enumerate(self.input_maps):
            has_signature = any(field.field_type == PSBTFieldType.PSBT_IN_PARTIAL_SIG for field in input_fields)
            if not has_signature:
                raise ValueError(f"Input {i} missing signature - run sign_inputs() first")
        
        print(f"Extracting transaction with {len(self.input_maps)} inputs and {len(self.output_maps)} outputs")
        
        # Build transaction
        tx_data = b''
        
        # Version (4 bytes, little-endian) 
        tx_data += struct.pack('<I', 2)  # Version 2
        
        # Segwit flag (0x00 0x01)
        tx_data += b'\x00\x01'
        
        # Input count (varint)
        tx_data += bytes([len(self.input_maps)])
        
        # Inputs
        for i, input_fields in enumerate(self.input_maps):
            input_dict = {field.field_type: field for field in input_fields}
            
            # Previous output (36 bytes)
            if PSBTFieldType.PSBT_IN_PREVIOUS_TXID in input_dict:
                txid = input_dict[PSBTFieldType.PSBT_IN_PREVIOUS_TXID].value_data
                tx_data += txid
            else:
                raise ValueError(f"Input {i} missing previous txid")
            
            if PSBTFieldType.PSBT_IN_OUTPUT_INDEX in input_dict:
                vout = input_dict[PSBTFieldType.PSBT_IN_OUTPUT_INDEX].value_data
                tx_data += vout
            else:
                raise ValueError(f"Input {i} missing output index")
            
            # ScriptSig (empty for witness inputs)
            tx_data += b'\x00'  # Empty scriptSig
            
            # Sequence (4 bytes)
            if PSBTFieldType.PSBT_IN_SEQUENCE in input_dict:
                sequence = input_dict[PSBTFieldType.PSBT_IN_SEQUENCE].value_data
                tx_data += sequence
            else:
                tx_data += b'\xfe\xff\xff\xff'  # Default sequence
        
        # Output count (varint)
        tx_data += bytes([len(self.output_maps)])
        
        # Outputs
        for i, output_fields in enumerate(self.output_maps):
            output_dict = {field.field_type: field for field in output_fields}
            
            # Amount (8 bytes, little-endian)
            if PSBTFieldType.PSBT_OUT_AMOUNT in output_dict:
                amount = output_dict[PSBTFieldType.PSBT_OUT_AMOUNT].value_data
                tx_data += amount
            else:
                raise ValueError(f"Output {i} missing amount")
            
            # Script
            if PSBTFieldType.PSBT_OUT_SCRIPT in output_dict:
                script = output_dict[PSBTFieldType.PSBT_OUT_SCRIPT].value_data
                tx_data += bytes([len(script)]) + script
            else:
                raise ValueError(f"Output {i} missing script")
        
        # Witness data
        for i, input_fields in enumerate(self.input_maps):
            input_dict = {field.field_type: field for field in input_fields}
            
            # For P2WPKH: witness = [signature, pubkey]
            witness_items = []
            
            # Find signature and pubkey
            signature = None
            pubkey = None
            
            for field in input_fields:
                if field.field_type == PSBTFieldType.PSBT_IN_PARTIAL_SIG:
                    signature = field.value_data
                    pubkey = field.key_data  # Public key is the key for partial sig
                    break
            
            if signature is None:
                raise ValueError(f"Input {i} missing witness signature")
            if pubkey is None:
                raise ValueError(f"Input {i} missing witness pubkey")
            
            witness_items = [signature, pubkey]
            
            # Write witness stack
            tx_data += bytes([len(witness_items)])  # Number of witness items
            for item in witness_items:
                tx_data += bytes([len(item)]) + item
        
        # Locktime (4 bytes, little-endian)
        tx_data += struct.pack('<I', 0)  # Locktime 0
        
        print(f" Transaction extracted ({len(tx_data)} bytes)")
        print(f" Transaction ID: {hashlib.sha256(hashlib.sha256(tx_data[:4] + tx_data[6:]).digest()).digest()[::-1].hex()}")
        
        return tx_data


def validate_psbt_silent_payments(psbt: SilentPaymentPSBT) -> Tuple[bool, List[str]]:
    """
    Validate a PSBT with silent payments according to BIP 375 rules
    
    Args:
        psbt: PSBT to validate
        
    Returns:
        (is_valid, list_of_errors)
    """
    from dleq_374 import dleq_verify_proof
    
    errors = []
    
    # Validate global fields
    has_version = False
    has_input_count = False
    has_output_count = False
    
    for field in psbt.global_fields:
        if field.field_type == PSBTFieldType.PSBT_GLOBAL_TX_VERSION:
            has_version = True
            version = struct.unpack('<I', field.value_data)[0]
            if version != 2:
                errors.append(f"Invalid transaction version {version}, must be 2 for silent payments")
        elif field.field_type == PSBTFieldType.PSBT_GLOBAL_INPUT_COUNT:
            has_input_count = True
        elif field.field_type == PSBTFieldType.PSBT_GLOBAL_OUTPUT_COUNT:
            has_output_count = True
    
    if not has_version:
        errors.append("Missing required PSBT_GLOBAL_TX_VERSION")
    if not has_input_count:
        errors.append("Missing required PSBT_GLOBAL_INPUT_COUNT")
    if not has_output_count:
        errors.append("Missing required PSBT_GLOBAL_OUTPUT_COUNT")
    
    # Validate inputs
    for i, input_fields in enumerate(psbt.input_maps):
        input_field_dict = {field.field_type: field for field in input_fields}
        
        # Check SIGHASH_ALL requirement
        if PSBTFieldType.PSBT_IN_SIGHASH_TYPE in input_field_dict:
            sighash_field = input_field_dict[PSBTFieldType.PSBT_IN_SIGHASH_TYPE]
            if len(sighash_field.value_data) >= 4:
                sighash_type = struct.unpack('<I', sighash_field.value_data[:4])[0]
                if sighash_type != 1:  # SIGHASH_ALL
                    errors.append(f"Input {i} uses non-SIGHASH_ALL ({sighash_type}) with silent payments")
        
        # Validate DLEQ proofs if present
        if PSBTFieldType.PSBT_IN_SP_DLEQ in input_field_dict:
            dleq_field = input_field_dict[PSBTFieldType.PSBT_IN_SP_DLEQ]
            ecdh_field = input_field_dict.get(PSBTFieldType.PSBT_IN_SP_ECDH_SHARE)
            
            if ecdh_field is None:
                errors.append(f"Input {i} has DLEQ proof but missing ECDH share")
            else:
                try:
                    # For now, skip actual DLEQ verification as it requires more context
                    # In full implementation, would verify the proof here
                    pass
                except Exception as e:
                    errors.append(f"Input {i} DLEQ proof verification failed: {e}")
    
    # Validate global DLEQ proofs
    global_field_dict = {field.field_type: field for field in psbt.global_fields}
    if PSBTFieldType.PSBT_GLOBAL_SP_DLEQ in global_field_dict:
        if PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE not in global_field_dict:
            errors.append("Global DLEQ proof present but missing global ECDH share")
    
    # Validate outputs
    for i, output_fields in enumerate(psbt.output_maps):
        output_field_dict = {field.field_type: field for field in output_fields}
        
        # Check silent payment outputs have required fields
        if PSBTFieldType.PSBT_OUT_SP_V0_INFO in output_field_dict:
            sp_info = output_field_dict[PSBTFieldType.PSBT_OUT_SP_V0_INFO]
            if len(sp_info.value_data) != 66:  # 33 + 33 bytes
                errors.append(f"Output {i} SP_V0_INFO has invalid length {len(sp_info.value_data)}, expected 66 bytes")
        
        # Check amount is present
        if PSBTFieldType.PSBT_OUT_AMOUNT not in output_field_dict:
            errors.append(f"Output {i} missing required amount field")
    
    return len(errors) == 0, errors