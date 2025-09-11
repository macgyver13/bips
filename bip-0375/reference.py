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
import base64
import struct
from typing import Dict, List, Tuple

# External dependencies for cryptographic operations
from dleq_374 import dleq_verify_proof
from secp256k1_374 import GE


# PSBT v2 + BIP 375 field types as class-based constants
class PSBTFieldType:
    # Standard PSBT v2 global fields
    PSBT_GLOBAL_UNSIGNED_TX = 0x00
    PSBT_GLOBAL_XPUB = 0x01
    PSBT_GLOBAL_TX_VERSION = 0x02
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

def validate_bip375_psbt(psbt_data: bytes, input_keys: List[Dict] = None) -> Tuple[bool, str]:
    """
    Validate a PSBT according to BIP 375 rules
    
    Args:
        psbt_data: Raw PSBT bytes
        
    Returns:
        (is_valid, error_message)
    """

    # Basic PSBT structure validation
    if len(psbt_data) < 5 or psbt_data[:5] != b'psbt\xff':
        return False, "Invalid PSBT magic"
    
    # Parse PSBT fields
    global_fields, input_maps, output_maps = parse_psbt_structure(psbt_data)
    
    # Rule 1: Check if silent payment outputs exist
    has_silent_outputs = any(
        PSBTFieldType.PSBT_OUT_SP_V0_INFO in output_fields 
        for output_fields in output_maps
    )
    
    if not has_silent_outputs:
        # If no silent payment outputs, this is just a regular PSBT v2
        return True, "Valid PSBT v2 (no silent payments)"
    
    # Rule 2: Critical structural validation - SP_V0_INFO field sizes
    for i, output_fields in enumerate(output_maps):
        if PSBTFieldType.PSBT_OUT_SP_V0_INFO in output_fields:
            sp_info = output_fields[PSBTFieldType.PSBT_OUT_SP_V0_INFO]
            if len(sp_info) != 66:  # 33 + 33 bytes for scan_key + spend_key
                return False, f"Output {i} SP_V0_INFO has wrong size ({len(sp_info)} bytes, expected 66)"
    
    # TODO: Must contain PSBT_OUT_SCRIPT and/or PSBTFieldType.PSBT_OUT_SP_V0_INFO

    # Rule 3: Critical structural validation - ECDH shares must exist
    has_global_ecdh = PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE in global_fields
    has_input_ecdh = any(
        PSBTFieldType.PSBT_IN_SP_ECDH_SHARE in input_fields
        for input_fields in input_maps
    )
    
    if not has_global_ecdh and not has_input_ecdh:
        return False, "Silent payment outputs present but no ECDH shares found"
    
    # Rule 4: Critical structural validation - DLEQ proofs must exist for ECDH shares
    if has_global_ecdh:
        has_global_dleq = PSBTFieldType.PSBT_GLOBAL_SP_DLEQ in global_fields
        if not has_global_dleq:
            return False, "Global ECDH share present but missing DLEQ proof"
    
    if has_input_ecdh:
        for i, input_fields in enumerate(input_maps):
            if PSBTFieldType.PSBT_IN_SP_ECDH_SHARE in input_fields:
                if PSBTFieldType.PSBT_IN_SP_DLEQ not in input_fields:
                    return False, f"Input {i} has ECDH share but missing DLEQ proof"
    
    # Rule 5: Cryptographic validation - verify DLEQ proofs
    if has_global_ecdh:
        if not validate_global_dleq_proof(global_fields, input_maps, input_keys):
            return False, "Global DLEQ proof verification failed"
    
    if has_input_ecdh:
        for i, input_fields in enumerate(input_maps):
            if PSBTFieldType.PSBT_IN_SP_ECDH_SHARE in input_fields:
                if not validate_input_dleq_proof(input_fields, input_keys, i):
                    return False, f"Input {i} DLEQ proof verification failed"
    
    # Rule 6: Transaction policy validation - segwit version restrictions
    for i, input_fields in enumerate(input_maps):
        if PSBTFieldType.PSBT_IN_WITNESS_UTXO in input_fields:
            witness_utxo = input_fields[PSBTFieldType.PSBT_IN_WITNESS_UTXO]
            if check_invalid_segwit_version(witness_utxo):
                return False, f"Input {i} uses segwit version > 1 with silent payments"
    
    # Rule 7: Transaction policy validation - SIGHASH_ALL requirement
    for i, input_fields in enumerate(input_maps):
        if PSBTFieldType.PSBT_IN_SIGHASH_TYPE in input_fields:
            sighash = input_fields[PSBTFieldType.PSBT_IN_SIGHASH_TYPE]
            if len(sighash) >= 4:
                sighash_type = struct.unpack('<I', sighash[:4])[0]
                if sighash_type != 1:  # SIGHASH_ALL
                    return False, f"Input {i} uses non-SIGHASH_ALL ({sighash_type}) with silent payments"
    
    return True, "Valid BIP 375 PSBT"


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
            
            # Extract field type and handle key-value pairs
            if key_data:
                field_type = key_data[0]
                key_content = key_data[1:] if len(key_data) > 1 else b''
                
                # For BIP 375 fields, store both key and value
                if field_type in [
                    PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE,
                    PSBTFieldType.PSBT_GLOBAL_SP_DLEQ,
                    PSBTFieldType.PSBT_IN_SP_ECDH_SHARE,
                    PSBTFieldType.PSBT_IN_SP_DLEQ
                ]:
                    fields[field_type] = {
                        'key': key_content,
                        'value': value_data
                    }
                else:
                    # For standard PSBT fields, just store value
                    fields[field_type] = value_data
        
        return fields, offset
    
    if len(psbt_data) < 5 or psbt_data[:5] != b'psbt\xff':
        raise ValueError("Invalid PSBT magic")
    
    offset = 5
    
    # Parse global section
    global_fields, offset = parse_section(psbt_data, offset)
    
    # Determine number of inputs and outputs (standard PSBT fields)
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


def validate_global_dleq_proof(global_fields: Dict[int, bytes], input_maps: List[Dict[int, bytes]] = None, input_keys: List[Dict] = None) -> bool:
    """Validate global DLEQ proof using BIP 374 implementation"""
    if PSBTFieldType.PSBT_GLOBAL_SP_DLEQ not in global_fields:
        return False
    if PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE not in global_fields:
        return False
        
    # Extract DLEQ and ECDH field data  
    dleq_field = global_fields[PSBTFieldType.PSBT_GLOBAL_SP_DLEQ]
    ecdh_field = global_fields[PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE]
    
    # Extract key and value components
    proof = dleq_field['value']
    scan_key_from_dleq = dleq_field['key']
    ecdh_share_bytes = ecdh_field['value']  
    scan_key_from_ecdh = ecdh_field['key']
    
    if len(proof) != 64:
        return False
    
    # Validate BIP 375 key-value structure
    if len(scan_key_from_ecdh) != 33:  # Key field should be 33-byte scan key
        return False
    if len(ecdh_share_bytes) != 33:  # Value field should be 33-byte ECDH result
        return False
    if len(scan_key_from_dleq) != 33:  # DLEQ key field should also be 33-byte scan key
        return False
    
    # Verify scan keys match between ECDH and DLEQ fields
    if scan_key_from_ecdh != scan_key_from_dleq:
        return False
        
    scan_key_bytes = scan_key_from_ecdh
        
    # Convert to GE points
    B = GE.from_bytes(scan_key_bytes)  # scan key
    C = GE.from_bytes(ecdh_share_bytes)  # ECDH result
    
    # For global ECDH shares, we need to combine all input public keys
    # According to BIP 375: "Let A_n be the sum of the public keys A of all eligible inputs"
    if not input_maps:
        # No input data available, fall back to structural validation
        return len(proof) == 64 and not B.infinity and not C.infinity
    
    A_combined = None
    
    # Method 1: Use test vector input keys if available (preferred)
    if input_keys:
        for input_key in input_keys:
            input_pubkey_hex = input_key['public_key']
            input_pubkey_bytes = bytes.fromhex(input_pubkey_hex)
            input_pubkey = GE.from_bytes(input_pubkey_bytes)
            
            if A_combined is None:
                A_combined = input_pubkey
            else:
                A_combined = A_combined + input_pubkey
    else:
        # Method 2: Extract and combine public keys from PSBT fields
        for input_fields in input_maps:
            input_pubkey = None
            
            # Try BIP32 derivation field
            if PSBTFieldType.PSBT_IN_BIP32_DERIVATION in input_fields:
                derivation_data = input_fields[PSBTFieldType.PSBT_IN_BIP32_DERIVATION]
                # BIP32 derivation format in PSBT: <pubkey><fingerprint><path>
                for offset in range(0, len(derivation_data), 33 + 4 + 4):
                    if offset + 33 <= len(derivation_data):
                        try:
                            pubkey_candidate = derivation_data[offset:offset + 33]
                            input_pubkey = GE.from_bytes(pubkey_candidate)
                            break
                        except Exception:
                            continue
            
            if input_pubkey is not None:
                if A_combined is None:
                    A_combined = input_pubkey
                else:
                    A_combined = A_combined + input_pubkey
    
    if A_combined is None:
        return False

    return dleq_verify_proof(A_combined, B, C, proof)


def validate_input_dleq_proof(input_fields: Dict[int, bytes], input_keys: List[Dict] = None, input_index: int = None) -> bool:
    """Validate input DLEQ proof using BIP 374 implementation"""

    if PSBTFieldType.PSBT_IN_SP_DLEQ not in input_fields:
        return False
    if PSBTFieldType.PSBT_IN_SP_ECDH_SHARE not in input_fields:
        return False
        
    # Extract DLEQ and ECDH field data
    dleq_field = input_fields[PSBTFieldType.PSBT_IN_SP_DLEQ]
    ecdh_field = input_fields[PSBTFieldType.PSBT_IN_SP_ECDH_SHARE]
    
    # Extract key and value components
    proof = dleq_field['value']
    scan_key_from_dleq = dleq_field['key']
    ecdh_share_bytes = ecdh_field['value']
    scan_key_from_ecdh = ecdh_field['key']
    
    if len(proof) != 64:
        return False
    
    # Validate BIP 375 key-value structure
    if len(scan_key_from_ecdh) != 33:  # Key field should be 33-byte scan key
        return False
    if len(ecdh_share_bytes) != 33:  # Value field should be 33-byte ECDH result
        return False
    if len(scan_key_from_dleq) != 33:  # DLEQ key field should also be 33-byte scan key
        return False
    
    # Verify scan keys match between ECDH and DLEQ fields
    if scan_key_from_ecdh != scan_key_from_dleq:
        return False
        
    scan_key_bytes = scan_key_from_ecdh
        
    # Convert to GE points
    B = GE.from_bytes(scan_key_bytes)  # scan key
    C = GE.from_bytes(ecdh_share_bytes)  # ECDH result
    
    # Extract input public key A from available sources
    A = None
    
    # TODO: Sum private keys from inputs or use ECDH_SHARE?
    # Method 1: Use test vector input keys if available and input_index is provided
    if input_keys and input_index is not None and input_index < len(input_keys):
        input_key = input_keys[input_index]
        pubkey_hex = input_key['public_key']
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        try:
            A = GE.from_bytes(pubkey_bytes)
        except Exception:
            pass  # Fall back to PSBT field extraction
    
    # Method 2: Try BIP32 derivation field (fallback)
    if A is None and PSBTFieldType.PSBT_IN_BIP32_DERIVATION in input_fields:
        derivation_data = input_fields[PSBTFieldType.PSBT_IN_BIP32_DERIVATION]
        # BIP32 derivation format: <pubkey><fingerprint><path>
        # We need the key part of the key-value pair
        for offset in range(0, len(derivation_data), 33 + 4 + 4):  # pubkey + fingerprint + path element
            if offset + 33 <= len(derivation_data):
                try:
                    pubkey_candidate = derivation_data[offset:offset + 33]
                    A = GE.from_bytes(pubkey_candidate)
                    break
                except Exception:
                    continue
    
    # Method 3: Try witness UTXO script extraction for P2WPKH (fallback)
    if A is None and PSBTFieldType.PSBT_IN_WITNESS_UTXO in input_fields:
        witness_utxo = input_fields[PSBTFieldType.PSBT_IN_WITNESS_UTXO]
        if len(witness_utxo) >= 9:
            script_len = witness_utxo[8]
            if script_len == 22:  # P2WPKH script length
                script = witness_utxo[9:9 + script_len]
                if len(script) == 22 and script[0] == 0x00 and script[1] == 0x14:
                    # P2WPKH script: OP_0 <20-byte pubkey hash>
                    # We can't extract the pubkey directly from the hash
                    pass
    
    # Method 4: Try other extraction methods if needed
    assert A, "Could not extract public key to validate input dleq proof"
    
    # Perform full DLEQ verification
    return dleq_verify_proof(A, B, C, proof)


def check_invalid_segwit_version(witness_utxo: bytes) -> bool:
    """Check if witness UTXO uses invalid segwit version for silent payments"""

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


def run_test_case(psbt_b64: str,
                  input_keys: List[Dict] = None, 
                  expected_ecdh_shares: List[Dict] = None) -> Tuple[bool, str]:
    """
    Enhanced test case runner that uses cryptographic material from test vectors
    
    Args:
        psbt_b64: Base64-encoded PSBT
        input_keys: List of input key material from test vector
        expected_ecdh_shares: Expected ECDH computation results
    
    Returns:
        (test_passed, error_message)
    """
    
    # Decode PSBT and run BIP 375 validation first
    psbt_data = base64.b64decode(psbt_b64)
    bip375_is_valid, bip375_error = validate_bip375_psbt(psbt_data, input_keys)
    
    # If BIP 375 validation fails, exit early
    if not bip375_is_valid:
        return False, bip375_error
    
    # If no validation material provided, return BIP 375 result
    if not (input_keys and expected_ecdh_shares):
        return bip375_is_valid, bip375_error
    
    # Perform DLEQ validation using the test vector material
    for ecdh_share in expected_ecdh_shares:
        scan_key_hex = ecdh_share['scan_key']
        ecdh_result_hex = ecdh_share['ecdh_result']  
        expected_proof_hex = ecdh_share['dleq_proof']
        assert expected_proof_hex, "Missing DLEQ proof in test vector"
        
        # Convert hex to bytes
        scan_key_bytes = bytes.fromhex(scan_key_hex)
        ecdh_result_bytes = bytes.fromhex(ecdh_result_hex)
        expected_proof = bytes.fromhex(expected_proof_hex)
        
        # Convert to GE points
        B = GE.from_bytes(scan_key_bytes)  # scan key
        C = GE.from_bytes(ecdh_result_bytes)  # ECDH result
        
        # Test DLEQ proof against the appropriate input key(s)
        input_index = ecdh_share.get('input_index')
        if input_index is not None:
            # Per-input ECDH share - test against specific input key
            input_key = input_keys[input_index]
            input_pubkey_hex = input_key['public_key']
            input_pubkey_bytes = bytes.fromhex(input_pubkey_hex)
            
            A = GE.from_bytes(input_pubkey_bytes)  # input public key
            proof_verified = dleq_verify_proof(A, B, C, expected_proof)
        else:
            # Global ECDH share - combine all input keys and test against sum
            A_combined = None
            for input_key in input_keys:
                input_pubkey_hex = input_key['public_key']
                input_pubkey_bytes = bytes.fromhex(input_pubkey_hex)
                A_i = GE.from_bytes(input_pubkey_bytes)
                
                if A_combined is None:
                    A_combined = A_i
                else:
                    A_combined = A_combined + A_i
            
            if A_combined is None:
                return False, "No input keys found for global ECDH share"
            
            # Test DLEQ proof against combined public key
            proof_verified = dleq_verify_proof(A_combined, B, C, expected_proof)

        
        # Check if proof verification succeeded
        if not proof_verified:
            return False, f"DLEQ proof verification failed for scan key {scan_key_hex[:16]}..."
    
    return True, "Enhanced validation passed"

if __name__ == "__main__":
    print("BIP 375 Reference Implementation")
    print("Use test_runner.py -f test_vectors.json")
    
    # TODO: Add basic demonstration once functions are implemented