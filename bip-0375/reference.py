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
from typing import Dict, List, Tuple, Optional

# External dependencies for cryptographic operations
from dleq_374 import dleq_verify_proof
from secp256k1_374 import GE
from bip352_utils import (
    compute_bip352_output_script,
    is_p2wpkh,
    is_p2sh,
    is_eligible_input_type,
    parse_non_witness_utxo,
)


# Minimal PSBT field type constants for reference implementation
# Full constant list available in psbt_sp/constants.py
class PSBTFieldType:
    """Minimal BIP 375 field types needed for reference validator"""

    # Global fields (required for validation)
    PSBT_GLOBAL_TX_VERSION = 0x02
    PSBT_GLOBAL_INPUT_COUNT = 0x04
    PSBT_GLOBAL_OUTPUT_COUNT = 0x05
    PSBT_GLOBAL_VERSION = 0xFB
    PSBT_GLOBAL_SP_ECDH_SHARE = 0x07
    PSBT_GLOBAL_SP_DLEQ = 0x08

    # Input fields (required for validation)
    PSBT_IN_NON_WITNESS_UTXO = 0x00
    PSBT_IN_WITNESS_UTXO = 0x01
    PSBT_IN_PARTIAL_SIG = 0x02
    PSBT_IN_SIGHASH_TYPE = 0x03
    PSBT_IN_REDEEM_SCRIPT = 0x04
    PSBT_IN_BIP32_DERIVATION = 0x06
    PSBT_IN_PREVIOUS_TXID = 0x0E
    PSBT_IN_OUTPUT_INDEX = 0x0F
    PSBT_IN_TAP_INTERNAL_KEY = 0x17
    PSBT_IN_SP_ECDH_SHARE = 0x1D
    PSBT_IN_SP_DLEQ = 0x1E

    # Output fields (required for validation)
    PSBT_OUT_AMOUNT = 0x03
    PSBT_OUT_SCRIPT = 0x04
    PSBT_OUT_SP_V0_INFO = 0x09
    PSBT_OUT_SP_V0_LABEL = 0x0A


def validate_bip375_psbt(
    psbt_data: bytes, input_keys: List[Dict] = None
) -> Tuple[bool, str]:
    """Validate a PSBT according to BIP 375 rules"""

    # Basic PSBT structure validation
    if len(psbt_data) < 5 or psbt_data[:5] != b"psbt\xff":
        return False, "Invalid PSBT magic"

    # Parse PSBT fields
    global_fields, input_maps, output_maps = parse_psbt_structure(psbt_data)

    # Rule 1: Check if silent payment outputs exist
    # Either SP_V0_INFO or SP_V0_LABEL indicates silent payment intent
    has_silent_outputs = any(
        PSBTFieldType.PSBT_OUT_SP_V0_INFO in output_fields
        or PSBTFieldType.PSBT_OUT_SP_V0_LABEL in output_fields
        for output_fields in output_maps
    )

    if not has_silent_outputs:
        # If no silent payment outputs, this is just a regular PSBT v2
        return True, "Valid PSBT v2 (no silent payments)"

    # Rule 2: Critical structural validation - SP_V0_INFO field sizes and PSBT_OUT_SCRIPT requirements
    for i, output_fields in enumerate(output_maps):
        # BIP375: Each output must have either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO (or both)
        has_script = PSBTFieldType.PSBT_OUT_SCRIPT in output_fields
        has_sp_info = PSBTFieldType.PSBT_OUT_SP_V0_INFO in output_fields
        has_sp_label = PSBTFieldType.PSBT_OUT_SP_V0_LABEL in output_fields

        if not has_script and not has_sp_info:
            return (
                False,
                f"Output {i} must have either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO",
            )

        # Rule 2a: PSBT_OUT_SP_V0_LABEL requires PSBT_OUT_SP_V0_INFO
        if has_sp_label and not has_sp_info:
            return (
                False,
                f"Output {i} has PSBT_OUT_SP_V0_LABEL but missing PSBT_OUT_SP_V0_INFO",
            )

        if has_sp_info:
            sp_info = output_fields[PSBTFieldType.PSBT_OUT_SP_V0_INFO]
            if len(sp_info) != 66:  # 33 + 33 bytes for scan_key + spend_key
                return (
                    False,
                    f"Output {i} SP_V0_INFO has wrong size ({len(sp_info)} bytes, expected 66)",
                )

    # Rule 3: Critical structural validation - ECDH shares must exist
    has_global_ecdh = PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE in global_fields
    has_input_ecdh = any(
        PSBTFieldType.PSBT_IN_SP_ECDH_SHARE in input_fields
        for input_fields in input_maps
    )

    if not has_global_ecdh and not has_input_ecdh:
        return False, "Silent payment outputs present but no ECDH shares found"

    # Rule 3a: Cannot have both global and per-input ECDH shares for same scan key
    if has_global_ecdh and has_input_ecdh:
        # Extract scan key from global ECDH share
        global_ecdh_field = global_fields[PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE]
        global_scan_key = global_ecdh_field["key"]

        # Check if any input has ECDH share for the same scan key
        for i, input_fields in enumerate(input_maps):
            if PSBTFieldType.PSBT_IN_SP_ECDH_SHARE in input_fields:
                input_ecdh_field = input_fields[PSBTFieldType.PSBT_IN_SP_ECDH_SHARE]
                input_scan_key = input_ecdh_field["key"]
                if input_scan_key == global_scan_key:
                    return (
                        False,
                        "Cannot have both global and per-input ECDH shares for same scan key",
                    )

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

    # Rule 7: Transaction policy validation - segwit version restrictions
    for i, input_fields in enumerate(input_maps):
        if PSBTFieldType.PSBT_IN_WITNESS_UTXO in input_fields:
            witness_utxo = input_fields[PSBTFieldType.PSBT_IN_WITNESS_UTXO]
            if check_invalid_segwit_version(witness_utxo):
                return False, f"Input {i} uses segwit version > 1 with silent payments"

    # Rule 6: Transaction policy validation - eligible input type requirement
    # When silent payment outputs exist, ALL inputs must be eligible types
    for i, input_fields in enumerate(input_maps):
        script_pubkey = None

        # Try WITNESS_UTXO first (segwit inputs)
        if PSBTFieldType.PSBT_IN_WITNESS_UTXO in input_fields:
            witness_utxo = input_fields[PSBTFieldType.PSBT_IN_WITNESS_UTXO]
            # Extract scriptPubKey from witness_utxo (skip 8-byte amount + 1-byte length)
            if len(witness_utxo) >= 9:
                script_len = witness_utxo[8]
                script_pubkey = witness_utxo[9 : 9 + script_len]

        # Try NON_WITNESS_UTXO for legacy inputs (P2PKH, P2SH)
        elif PSBTFieldType.PSBT_IN_NON_WITNESS_UTXO in input_fields:
            non_witness_utxo = input_fields[PSBTFieldType.PSBT_IN_NON_WITNESS_UTXO]
            # Get the output index from PSBT_IN_OUTPUT_INDEX field
            if PSBTFieldType.PSBT_IN_OUTPUT_INDEX in input_fields:
                output_index_bytes = input_fields[PSBTFieldType.PSBT_IN_OUTPUT_INDEX]
                if len(output_index_bytes) == 4:
                    output_index = struct.unpack("<I", output_index_bytes)[0]
                    script_pubkey = parse_non_witness_utxo(
                        non_witness_utxo, output_index
                    )

        if script_pubkey is None:
            return False, f"Input {i} missing UTXO information"

        if not is_eligible_input_type(script_pubkey):
            return False, f"Input {i} uses ineligible input type"

        # For P2SH, verify it's P2SH-P2WPKH
        if is_p2sh(script_pubkey):
            if PSBTFieldType.PSBT_IN_REDEEM_SCRIPT in input_fields:
                redeem_script = input_fields[PSBTFieldType.PSBT_IN_REDEEM_SCRIPT]
                # Verify redeemScript is P2WPKH
                if not is_p2wpkh(redeem_script):
                    return False, f"Input {i} P2SH is not P2SH-P2WPKH"
            else:
                return False, f"Input {i} P2SH missing PSBT_IN_REDEEM_SCRIPT"

    # Rule 8: Transaction policy validation - SIGHASH_ALL requirement
    for i, input_fields in enumerate(input_maps):
        if PSBTFieldType.PSBT_IN_SIGHASH_TYPE in input_fields:
            sighash = input_fields[PSBTFieldType.PSBT_IN_SIGHASH_TYPE]
            if len(sighash) >= 4:
                sighash_type = struct.unpack("<I", sighash[:4])[0]
                if sighash_type != 1:  # SIGHASH_ALL
                    return (
                        False,
                        f"Input {i} uses non-SIGHASH_ALL ({sighash_type}) with silent payments",
                    )

    return True, "Valid BIP 375 PSBT"


def parse_psbt_structure(
    psbt_data: bytes,
) -> Tuple[Dict[int, bytes], List[Dict[int, bytes]], List[Dict[int, bytes]]]:
    """Parse PSBT structure into global, input, and output field maps"""

    def parse_compact_size_uint(data: bytes, offset: int) -> Tuple[int, int]:
        """Parse compact size uint and return (value, new_offset)"""
        if offset >= len(data):
            raise ValueError("Not enough data")

        first_byte = data[offset]
        if first_byte < 0xFD:
            return first_byte, offset + 1
        elif first_byte == 0xFD:
            return struct.unpack("<H", data[offset + 1 : offset + 3])[0], offset + 3
        elif first_byte == 0xFE:
            return struct.unpack("<L", data[offset + 1 : offset + 5])[0], offset + 5
        else:
            return struct.unpack("<Q", data[offset + 1 : offset + 9])[0], offset + 9

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
            key_data = data[offset : offset + key_len]
            offset += key_len

            # Read value length
            value_len, offset = parse_compact_size_uint(data, offset)

            # Read value data
            if offset + value_len > len(data):
                raise ValueError("Truncated value data")
            value_data = data[offset : offset + value_len]
            offset += value_len

            # Extract field type and handle key-value pairs
            if key_data:
                field_type = key_data[0]
                key_content = key_data[1:] if len(key_data) > 1 else b""

                # For BIP 375 and BIP-174 key-value fields, store both key and value
                if field_type in [
                    PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE,
                    PSBTFieldType.PSBT_GLOBAL_SP_DLEQ,
                    PSBTFieldType.PSBT_IN_SP_ECDH_SHARE,
                    PSBTFieldType.PSBT_IN_SP_DLEQ,
                    PSBTFieldType.PSBT_IN_BIP32_DERIVATION,
                    PSBTFieldType.PSBT_IN_PARTIAL_SIG,
                ]:
                    fields[field_type] = {"key": key_content, "value": value_data}
                else:
                    # For standard PSBT fields, just store value
                    fields[field_type] = value_data

        return fields, offset

    if len(psbt_data) < 5 or psbt_data[:5] != b"psbt\xff":
        raise ValueError("Invalid PSBT magic")

    offset = 5

    # Parse global section
    global_fields, offset = parse_section(psbt_data, offset)

    # Determine number of inputs and outputs (standard PSBT fields)
    num_inputs = (
        global_fields.get(PSBTFieldType.PSBT_GLOBAL_INPUT_COUNT, b"\x00")[0]
        if PSBTFieldType.PSBT_GLOBAL_INPUT_COUNT in global_fields
        else 1
    )
    num_outputs = (
        global_fields.get(PSBTFieldType.PSBT_GLOBAL_OUTPUT_COUNT, b"\x00")[0]
        if PSBTFieldType.PSBT_GLOBAL_OUTPUT_COUNT in global_fields
        else 1
    )

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


def extract_dleq_components(
    dleq_field: Dict, ecdh_field: Dict
) -> Tuple[bytes, bytes, bytes]:
    """Extract and validate DLEQ proof components from PSBT fields"""

    # Extract key and value components
    proof = dleq_field["value"]
    dleq_scan_key_bytes = dleq_field["key"]
    ecdh_share_bytes = ecdh_field["value"]
    ecdh_scan_key_bytes = ecdh_field["key"]

    # Validate proof length
    if len(proof) != 64:
        raise ValueError(f"Invalid DLEQ proof length: {len(proof)} bytes (expected 64)")

    # Validate BIP 375 key-value structure
    if len(ecdh_scan_key_bytes) != 33:
        raise ValueError(
            f"Invalid ECDH scan key length: {len(ecdh_scan_key_bytes)} bytes (expected 33)"
        )
    if len(ecdh_share_bytes) != 33:
        raise ValueError(
            f"Invalid ECDH share length: {len(ecdh_share_bytes)} bytes (expected 33)"
        )
    if len(dleq_scan_key_bytes) != 33:
        raise ValueError(
            f"Invalid DLEQ scan key length: {len(dleq_scan_key_bytes)} bytes (expected 33)"
        )

    # Verify scan keys match between ECDH and DLEQ fields
    if ecdh_scan_key_bytes != dleq_scan_key_bytes:
        raise ValueError("Scan key mismatch between ECDH and DLEQ fields")

    return proof, ecdh_scan_key_bytes, ecdh_share_bytes


def validate_global_dleq_proof(
    global_fields: Dict[int, bytes],
    input_maps: List[Dict[int, bytes]] = None,
    input_keys: List[Dict] = None,
) -> bool:
    """Validate global DLEQ proof using BIP 374 implementation"""

    if PSBTFieldType.PSBT_GLOBAL_SP_DLEQ not in global_fields:
        return False
    if PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE not in global_fields:
        return False

    # Extract and validate components
    try:
        proof, scan_key_bytes, ecdh_share_bytes = extract_dleq_components(
            global_fields[PSBTFieldType.PSBT_GLOBAL_SP_DLEQ],
            global_fields[PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE],
        )
    except ValueError:
        return False

    # Convert to GE points
    B = GE.from_bytes(scan_key_bytes)  # scan key
    C = GE.from_bytes(ecdh_share_bytes)  # ECDH result

    # For global ECDH shares, we need to combine all input public keys
    # According to BIP 375: "Let A_n be the sum of the public keys A of all eligible inputs"
    if not input_maps:
        # No input data available, fall back to structural validation
        return len(proof) == 64 and not B.infinity and not C.infinity

    A_combined = None

    # Method 1: Extract and combine public keys from PSBT fields (preferred, BIP-174 standard)
    for input_fields in input_maps:
        input_pubkey = get_pubkey_from_input(input_fields)

        if input_pubkey is not None:
            if A_combined is None:
                A_combined = input_pubkey
            else:
                A_combined = A_combined + input_pubkey

    # Method 2: Use test vector input keys if PSBT fields didn't provide pubkeys (fallback)
    if A_combined is None and input_keys:
        for input_key in input_keys:
            input_pubkey_hex = input_key["public_key"]
            input_pubkey_bytes = bytes.fromhex(input_pubkey_hex)
            input_pubkey = GE.from_bytes(input_pubkey_bytes)

            if A_combined is None:
                A_combined = input_pubkey
            else:
                A_combined = A_combined + input_pubkey

    if A_combined is None:
        return False

    return dleq_verify_proof(A_combined, B, C, proof)


def validate_input_dleq_proof(
    input_fields: Dict[int, bytes],
    input_keys: List[Dict] = None,
    input_index: int = None,
) -> bool:
    """Validate input DLEQ proof using BIP 374 implementation"""

    if PSBTFieldType.PSBT_IN_SP_DLEQ not in input_fields:
        return False
    if PSBTFieldType.PSBT_IN_SP_ECDH_SHARE not in input_fields:
        return False

    # Extract and validate components
    try:
        proof, scan_key_bytes, ecdh_share_bytes = extract_dleq_components(
            input_fields[PSBTFieldType.PSBT_IN_SP_DLEQ],
            input_fields[PSBTFieldType.PSBT_IN_SP_ECDH_SHARE],
        )
    except ValueError:
        return False

    # Convert to GE points
    B = GE.from_bytes(scan_key_bytes)  # scan key
    C = GE.from_bytes(ecdh_share_bytes)  # ECDH result

    # Extract input public key A from available sources
    A = get_pubkey_from_input(input_fields)

    # Fallback: Use test vector input keys if PSBT fields didn't provide pubkey
    if (
        A is None
        and input_keys
        and input_index is not None
        and input_index < len(input_keys)
    ):
        input_key = input_keys[input_index]
        pubkey_hex = input_key["public_key"]
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        try:
            A = GE.from_bytes(pubkey_bytes)
        except Exception:
            pass

    if A is None:
        return False

    # Perform full DLEQ verification
    return dleq_verify_proof(A, B, C, proof)


def get_pubkey_from_input(input_fields: Dict[int, bytes]) -> Optional[GE]:
    """Extract public key from PSBT input fields"""
    # Method 1: Try BIP32 derivation field (highest priority, BIP-174 standard)
    if PSBTFieldType.PSBT_IN_BIP32_DERIVATION in input_fields:
        derivation_data = input_fields[PSBTFieldType.PSBT_IN_BIP32_DERIVATION]
        # BIP32 derivation is stored as key-value pairs in PSBT
        # For BIP-375 test vectors: key = 33-byte pubkey, value = empty (privacy-preserving)
        if isinstance(derivation_data, dict):
            pubkey_candidate = derivation_data.get("key", b"")
            if len(pubkey_candidate) == 33:
                try:
                    return GE.from_bytes(pubkey_candidate)
                except Exception:
                    pass
        elif len(derivation_data) >= 33:
            try:
                return GE.from_bytes(derivation_data[:33])
            except Exception:
                pass

    # Method 2: Try Taproot internal key (fallback for Taproot inputs)
    if PSBTFieldType.PSBT_IN_TAP_INTERNAL_KEY in input_fields:
        tap_key = input_fields[PSBTFieldType.PSBT_IN_TAP_INTERNAL_KEY]
        if len(tap_key) == 32:
            try:
                # Taproot uses x-only pubkeys, need to reconstruct
                return GE.from_bytes_xonly(tap_key)
            except Exception:
                pass

    # Method 3: Try partial signature field (fallback for signed PSBTs)
    if PSBTFieldType.PSBT_IN_PARTIAL_SIG in input_fields:
        partial_sig_data = input_fields[PSBTFieldType.PSBT_IN_PARTIAL_SIG]
        if isinstance(partial_sig_data, dict):
            pubkey_candidate = partial_sig_data.get("key", b"")
            if len(pubkey_candidate) == 33:
                try:
                    return GE.from_bytes(pubkey_candidate)
                except Exception:
                    pass

    return None


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

    script = witness_utxo[offset : offset + script_len]

    # Check if it's segwit v2 or higher
    if len(script) >= 2 and script[0] >= 0x52:  # OP_2 or higher
        return True

    return False


def run_test_case(
    psbt_b64: str,
    input_keys: List[Dict] = None,
    expected_ecdh_shares: List[Dict] = None,
    correct_bip352_script: str = None,
) -> Tuple[bool, str]:
    """Enhanced test case runner that uses cryptographic material from test vectors"""

    # Decode PSBT and run BIP 375 validation first
    psbt_data = base64.b64decode(psbt_b64)
    bip375_is_valid, bip375_error = validate_bip375_psbt(psbt_data, input_keys)

    # If BIP 375 validation fails, exit early
    if not bip375_is_valid:
        return False, bip375_error

    # Additional validation: Compute and verify BIP-352 output scripts
    # This validates that output scripts match the silent payment derivation
    if input_keys and expected_ecdh_shares:
        global_fields, input_maps, output_maps = parse_psbt_structure(psbt_data)

        # Build outpoints list from PSBT inputs
        outpoints = []
        for input_fields in input_maps:
            if PSBTFieldType.PSBT_IN_PREVIOUS_TXID in input_fields:
                txid = input_fields[PSBTFieldType.PSBT_IN_PREVIOUS_TXID]
                output_index_bytes = input_fields.get(
                    PSBTFieldType.PSBT_IN_OUTPUT_INDEX, b"\x00\x00\x00\x00"
                )
                output_index = struct.unpack("<I", output_index_bytes)[0]
                outpoints.append((txid, output_index))

        # Validate each silent payment output
        for output_idx, output_fields in enumerate(output_maps):
            # Only validate outputs with SP_V0_INFO (silent payment outputs)
            if PSBTFieldType.PSBT_OUT_SP_V0_INFO not in output_fields:
                continue

            sp_info = output_fields[PSBTFieldType.PSBT_OUT_SP_V0_INFO]
            if len(sp_info) != 66:
                continue  # Already validated in structural checks

            scan_pubkey_bytes = sp_info[:33]
            spend_pubkey_bytes = sp_info[33:]

            # Find matching ECDH share for this scan key
            ecdh_share_bytes = None
            summed_pubkey_bytes = None

            # Check for global ECDH share
            if PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE in global_fields:
                global_ecdh = global_fields[PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE]
                if (
                    isinstance(global_ecdh, dict)
                    and global_ecdh.get("key") == scan_pubkey_bytes
                ):
                    ecdh_share_bytes = global_ecdh["value"]
                    # Combine all input public keys
                    summed_pubkey = None
                    for input_key in input_keys:
                        pubkey_bytes = bytes.fromhex(input_key["public_key"])
                        pubkey = GE.from_bytes(pubkey_bytes)
                        summed_pubkey = (
                            pubkey if summed_pubkey is None else summed_pubkey + pubkey
                        )
                    if summed_pubkey:
                        summed_pubkey_bytes = summed_pubkey.to_bytes_compressed()

            # Check for per-input ECDH shares (if no global share found)
            # BIP-375: When using per-input shares, sum all shares for the same scan key
            if not ecdh_share_bytes:
                summed_ecdh_share = None
                summed_pubkey = None

                for input_idx, input_fields in enumerate(input_maps):
                    if PSBTFieldType.PSBT_IN_SP_ECDH_SHARE in input_fields:
                        input_ecdh = input_fields[PSBTFieldType.PSBT_IN_SP_ECDH_SHARE]
                        if (
                            isinstance(input_ecdh, dict)
                            and input_ecdh.get("key") == scan_pubkey_bytes
                        ):
                            # Add this ECDH share to the sum
                            ecdh_share_point = GE.from_bytes(input_ecdh["value"])
                            summed_ecdh_share = (
                                ecdh_share_point
                                if summed_ecdh_share is None
                                else summed_ecdh_share + ecdh_share_point
                            )

                            # Add this input's public key to the sum
                            if input_idx < len(input_keys):
                                pubkey_bytes = bytes.fromhex(
                                    input_keys[input_idx]["public_key"]
                                )
                                pubkey = GE.from_bytes(pubkey_bytes)
                                summed_pubkey = (
                                    pubkey
                                    if summed_pubkey is None
                                    else summed_pubkey + pubkey
                                )

                if summed_ecdh_share and summed_pubkey:
                    ecdh_share_bytes = summed_ecdh_share.to_bytes_compressed()
                    summed_pubkey_bytes = summed_pubkey.to_bytes_compressed()

            # If we found ECDH share and summed pubkey, compute and verify output script
            if ecdh_share_bytes and summed_pubkey_bytes and outpoints:
                computed_script = compute_bip352_output_script(
                    outpoints=outpoints,
                    summed_pubkey_bytes=summed_pubkey_bytes,
                    ecdh_share_bytes=ecdh_share_bytes,
                    spend_pubkey_bytes=spend_pubkey_bytes,
                    k=output_idx,  # Use output index for k parameter
                )

                # Compare with actual PSBT output script
                if PSBTFieldType.PSBT_OUT_SCRIPT in output_fields:
                    actual_script = output_fields[PSBTFieldType.PSBT_OUT_SCRIPT]
                    if actual_script != computed_script:
                        return (
                            False,
                            f"Output {output_idx} script doesn't match BIP-352 derivation",
                        )

    # If no validation material provided, return BIP 375 result
    if not (input_keys and expected_ecdh_shares):
        return bip375_is_valid, bip375_error

    # Perform DLEQ validation using the test vector material
    for ecdh_share in expected_ecdh_shares:
        scan_key_hex = ecdh_share["scan_key"]
        ecdh_result_hex = ecdh_share["ecdh_result"]
        expected_proof_hex = ecdh_share["dleq_proof"]
        assert expected_proof_hex, "Missing DLEQ proof in test vector"

        # Convert hex to bytes
        scan_key_bytes = bytes.fromhex(scan_key_hex)
        ecdh_result_bytes = bytes.fromhex(ecdh_result_hex)
        expected_proof = bytes.fromhex(expected_proof_hex)

        # Convert to GE points
        B = GE.from_bytes(scan_key_bytes)  # scan key
        C = GE.from_bytes(ecdh_result_bytes)  # ECDH result

        # Test DLEQ proof against the appropriate input key(s)
        input_index = ecdh_share.get("input_index")
        if input_index is not None:
            # Per-input ECDH share - test against specific input key
            input_key = input_keys[input_index]
            input_pubkey_hex = input_key["public_key"]
            input_pubkey_bytes = bytes.fromhex(input_pubkey_hex)

            A = GE.from_bytes(input_pubkey_bytes)  # input public key
            proof_verified = dleq_verify_proof(A, B, C, expected_proof)
        else:
            # Global ECDH share - combine all input keys and test against sum
            A_combined = None
            for input_key in input_keys:
                input_pubkey_hex = input_key["public_key"]
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
            return False, f"DLEQ proof verification failed for scan key {scan_key_hex}"

    return True, "Enhanced validation passed"


# ==============================================================================
# Test Runner
# ==============================================================================


def load_test_vectors(filename: str) -> Dict:
    """Load test vectors from JSON file"""
    import json
    import sys

    try:
        with open(filename, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Test vector file '{filename}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in test vector file: {e}")
        sys.exit(1)


def parse_test(test_vector: Dict) -> tuple:
    """Parse test vector"""
    psbt_b64 = test_vector["psbt"]
    input_keys = test_vector.get("input_keys", [])
    expected_ecdh_shares = test_vector.get("expected_ecdh_shares", [])
    correct_bip352_script = test_vector.get("correct_bip352_script")

    return psbt_b64, input_keys, expected_ecdh_shares, correct_bip352_script


def run_tests(test_data: Dict, verbose: bool = False) -> None:
    """Run all complete test cases"""

    print("BIP 375 Reference Implementation - Test Runner")
    print("=" * 50)
    print(f"Description: {test_data['description']}")
    print(f"Version: {test_data['version']}")
    print(f"Invalid test cases: {len(test_data['invalid'])}")
    print(f"Valid test cases: {len(test_data['valid'])}")

    test_num = 1

    # Run invalid test cases
    print("\n=== Running Invalid Test Cases ===")
    for test_case in test_data["invalid"]:
        description = test_case["description"]
        expected_error = test_case.get("comment", "unknown error")

        print(f"Test {test_num}: {description}")

        psbt_b64, input_keys, expected_ecdh_shares, correct_bip352_script = parse_test(
            test_case
        )

        # Run the enhanced test case
        is_valid, error_msg = run_test_case(
            psbt_b64=psbt_b64,
            input_keys=input_keys,
            expected_ecdh_shares=expected_ecdh_shares,
            correct_bip352_script=correct_bip352_script,
        )

        assert not is_valid, error_msg
        if verbose:
            print(f"     Comment: {expected_error}")
            print(f"     Details: {error_msg}")
        test_num += 1

    # Run valid test cases
    print()
    print("=== Running Valid Test Cases ===")
    for test_case in test_data["valid"]:
        description = test_case["description"]

        print(f"Test {test_num}: {description}")
        if verbose:
            print(f"     Comment: {test_case.get('comment', '')}")

        psbt_b64, input_keys, expected_ecdh_shares, correct_bip352_script = parse_test(
            test_case
        )

        # Run the enhanced test case
        is_valid, error_msg = run_test_case(
            psbt_b64=psbt_b64,
            input_keys=input_keys,
            expected_ecdh_shares=expected_ecdh_shares,
            correct_bip352_script=correct_bip352_script,
        )

        assert is_valid, error_msg
        test_num += 1

    print(f"\n✓ All {test_num - 1} tests passed")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="BIP 375 Reference Implementation - Test Runner",
        epilog="For production use, see the psbt_sp package.",
    )
    parser.add_argument(
        "--test-file",
        "-f",
        default="test_vectors.json",
        help="Test vector file to run (default: test_vectors.json)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed error messages and exception details",
    )

    args = parser.parse_args()

    # Load test vectors
    test_data = load_test_vectors(args.test_file)

    # Run tests
    run_tests(test_data, args.verbose)
