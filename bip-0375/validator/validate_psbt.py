#!/usr/bin/env python3
"""
Validates PSBTs according to BIP-375 rules

Provides independent checks for PSBT structure, ECDH share coverage,
input eligibility, and output script correctness.
"""

import struct
from typing import Tuple

from deps.bitcoin_test.messages import COutPoint
from deps.bitcoin_test.psbt import (
    PSBT,
    PSBT_GLOBAL_TX_MODIFIABLE,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_OUT_SCRIPT,
)
from deps.dleq import dleq_verify_proof
from secp256k1lab.secp256k1 import GE

from .bip352_crypto import compute_silent_payment_output_script
from .inputs import (
    _is_p2tr,
    _script_pubkey_from_psbt_input,
    collect_input_ecdh_and_pubkey,
    input_signatures,
    is_input_eligible,
    pubkey_from_eligible_input,
)
from .psbt_bip375 import (
    PSBT_GLOBAL_SP_ECDH_SHARE,
    PSBT_GLOBAL_SP_DLEQ,
    PSBT_IN_SP_ECDH_SHARE,
    PSBT_IN_SP_DLEQ,
    PSBT_OUT_SP_V0_INFO,
    PSBT_OUT_SP_V0_LABEL,
)


def validate_psbt_structure(psbt: PSBT) -> Tuple[bool, str]:
    """
    Validate PSBT structure requirements

    Checks:
    - Each output must have PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO
    - PSBT_OUT_SP_V0_LABEL requires PSBT_OUT_SP_V0_INFO
    - SP_V0_LABEL must be 4 bytes (32-bit little-endian uint)
    - SP_V0_INFO must be 66 bytes (33-byte scan key + 33-byte spend key)
    - ECDH share and DLEQ proof keydata must be 33-byte scan keys
    - ECDH shares must be 33 bytes
    - DLEQ proofs must be 64 bytes
    - Scan keys, ECDH shares and SP_V0_INFO keys must be valid points
    - BIP-375 fields only in a version 2 PSBT
    - PSBT_IN_SIGHASH_TYPE must be 4 bytes
    """
    # BIP-375 defines its fields for PSBTv2 only
    if psbt.version != 2 and (
        psbt.g.get_all_by_type(PSBT_GLOBAL_SP_ECDH_SHARE)
        or psbt.g.get_all_by_type(PSBT_GLOBAL_SP_DLEQ)
        or any(
            input_map.get_all_by_type(PSBT_IN_SP_ECDH_SHARE)
            or input_map.get_all_by_type(PSBT_IN_SP_DLEQ)
            for input_map in psbt.i
        )
        or any(
            PSBT_OUT_SP_V0_INFO in output_map or PSBT_OUT_SP_V0_LABEL in output_map
            for output_map in psbt.o
        )
    ):
        return False, f"PSBT version {psbt.version} carries BIP-375 fields, which require version 2"

    for i, input_map in enumerate(psbt.i):
        sighash = input_map.get(PSBT_IN_SIGHASH_TYPE)
        if sighash is not None and len(sighash) != 4:
            return (
                False,
                f"Input {i} PSBT_IN_SIGHASH_TYPE has wrong length ({len(sighash)} bytes, expected 4)",
            )

    # Check output requirements
    for i, output_map in enumerate(psbt.o):
        has_script = (
            PSBT_OUT_SCRIPT in output_map and len(output_map[PSBT_OUT_SCRIPT]) > 0
        )
        has_sp_info = PSBT_OUT_SP_V0_INFO in output_map
        has_sp_label = PSBT_OUT_SP_V0_LABEL in output_map

        # Output must have script or SP info
        if not has_script and not has_sp_info:
            return (
                False,
                f"Output {i} must have either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO",
            )

        # SP label requires SP info
        if has_sp_label and not has_sp_info:
            return (
                False,
                f"Output {i} has PSBT_OUT_SP_V0_LABEL but missing PSBT_OUT_SP_V0_INFO",
            )

        # Validate SP_V0_LABEL field length
        if has_sp_label:
            sp_label = output_map[PSBT_OUT_SP_V0_LABEL]
            if len(sp_label) != 4:
                return (
                    False,
                    f"Output {i} PSBT_OUT_SP_V0_LABEL has wrong length ({len(sp_label)} bytes, expected 4)",
                )

        # Validate SP_V0_INFO field length
        if has_sp_info:
            sp_info = output_map[PSBT_OUT_SP_V0_INFO]
            if len(sp_info) != 66:
                return (
                    False,
                    f"Output {i} SP_V0_INFO has wrong length ({len(sp_info)} bytes, expected 66)",
                )

    # Validate ECDH share keydata and value lengths (global and per-input)
    global_ecdh_shares = psbt.g.get_all_by_type(PSBT_GLOBAL_SP_ECDH_SHARE)
    for scan_key, ecdh_share in global_ecdh_shares:
        if len(scan_key) != 33:
            return (
                False,
                f"Global ECDH share scan key has wrong length ({len(scan_key)} bytes, expected 33)",
            )
        if len(ecdh_share) != 33:
            return (
                False,
                f"Global ECDH share has wrong length ({len(ecdh_share)} bytes, expected 33)",
            )

    for i, input_map in enumerate(psbt.i):
        input_ecdh_shares = input_map.get_all_by_type(PSBT_IN_SP_ECDH_SHARE)
        for scan_key, ecdh_share in input_ecdh_shares:
            if len(scan_key) != 33:
                return (
                    False,
                    f"Input {i} ECDH share scan key has wrong length ({len(scan_key)} bytes, expected 33)",
                )
            if len(ecdh_share) != 33:
                return (
                    False,
                    f"Input {i} ECDH share has wrong length ({len(ecdh_share)} bytes, expected 33)",
                )

    # Validate DLEQ proof keydata and value lengths (global and per-input)
    global_dleq_proofs = psbt.g.get_all_by_type(PSBT_GLOBAL_SP_DLEQ)
    for scan_key, dleq_proof in global_dleq_proofs:
        if len(scan_key) != 33:
            return (
                False,
                f"Global DLEQ proof scan key has wrong length ({len(scan_key)} bytes, expected 33)",
            )
        if len(dleq_proof) != 64:
            return (
                False,
                f"Global DLEQ proof has wrong length ({len(dleq_proof)} bytes, expected 64)",
            )

    for i, input_map in enumerate(psbt.i):
        input_dleq_proofs = input_map.get_all_by_type(PSBT_IN_SP_DLEQ)
        for scan_key, dleq_proof in input_dleq_proofs:
            if len(scan_key) != 33:
                return (
                    False,
                    f"Input {i} DLEQ proof scan key has wrong length ({len(scan_key)} bytes, expected 33)",
                )
            if len(dleq_proof) != 64:
                return (
                    False,
                    f"Input {i} DLEQ proof has wrong length ({len(dleq_proof)} bytes, expected 64)",
                )

    # Validate that every 33-byte key and ECDH share checked above is a valid point
    points = []
    for i, output_map in enumerate(psbt.o):
        if PSBT_OUT_SP_V0_INFO in output_map:
            sp_info = output_map[PSBT_OUT_SP_V0_INFO]
            points.append((sp_info[:33], f"Output {i} SP_V0_INFO scan key"))
            points.append((sp_info[33:], f"Output {i} SP_V0_INFO spend key"))
    maps = [("Global", psbt.g, PSBT_GLOBAL_SP_ECDH_SHARE, PSBT_GLOBAL_SP_DLEQ)] + [
        (f"Input {i}", input_map, PSBT_IN_SP_ECDH_SHARE, PSBT_IN_SP_DLEQ)
        for i, input_map in enumerate(psbt.i)
    ]
    for context, psbt_map, ecdh_type, dleq_type in maps:
        for scan_key, ecdh_share in psbt_map.get_all_by_type(ecdh_type):
            points.append((scan_key, f"{context} ECDH share scan key"))
            points.append((ecdh_share, f"{context} ECDH share"))
        for scan_key, _ in psbt_map.get_all_by_type(dleq_type):
            points.append((scan_key, f"{context} DLEQ proof scan key"))
    for point, name in points:
        if not _is_valid_point(point):
            return False, f"{name} is not a valid point"

    return True, None


def _is_valid_point(b: bytes) -> bool:
    """Return whether b is a valid compressed secp256k1 point."""
    try:
        GE.from_bytes_compressed(b)
    except ValueError:
        return False
    return True


def validate_ecdh_coverage(psbt: PSBT) -> Tuple[bool, str]:
    """
    Validate ECDH share coverage and DLEQ proof correctness

    Checks:
    - Verify ECDH share coverage for each scan key associated with SP outputs
    - Every ECDH share must have a corresponding DLEQ proof
    - If PSBT_OUT_SCRIPT is set, all eligible inputs must have ECDH coverage
    - DLEQ proofs must verify correctly
    """
    # Collect unique scan keys from SP outputs
    scan_keys = set()
    for output_map in psbt.o:
        if PSBT_OUT_SP_V0_INFO in output_map:
            sp_info = output_map[PSBT_OUT_SP_V0_INFO]
            scan_keys.add(sp_info[:33])

    if not scan_keys:
        return True, None  # No SP outputs, nothing to check

    # For each scan key, verify ECDH share coverage and DLEQ proofs
    for scan_key in scan_keys:
        has_global_ecdh = psbt.g.get_by_key(PSBT_GLOBAL_SP_ECDH_SHARE, scan_key)
        has_input_ecdh = any(
            input_map.get_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key)
            for input_map in psbt.i
        )

        scan_key_has_computed_output = any(
            PSBT_OUT_SP_V0_INFO in om
            and om[PSBT_OUT_SP_V0_INFO][:33] == scan_key
            and PSBT_OUT_SCRIPT in om
            for om in psbt.o
        )
        if scan_key_has_computed_output and not has_global_ecdh and not has_input_ecdh:
            return False, "Silent payment output present but no ECDH share for scan key"

        # Verify global DLEQ proof if global ECDH present
        if has_global_ecdh:
            ecdh_share = psbt.g.get_by_key(PSBT_GLOBAL_SP_ECDH_SHARE, scan_key)
            dleq_proof = psbt.g.get_by_key(PSBT_GLOBAL_SP_DLEQ, scan_key)
            if not dleq_proof:
                return False, "Global ECDH share missing DLEQ proof"

            # BIP-375 verifies a global share against the sum of every eligible
            # input's pubkey, so each one must be recoverable
            for i, input_map in enumerate(psbt.i):
                if is_input_eligible(input_map) and pubkey_from_eligible_input(input_map) is None:
                    return (
                        False,
                        f"Global ECDH share set but eligible input {i} has no public key",
                    )
            _, summed_pubkey_bytes = collect_input_ecdh_and_pubkey(psbt, scan_key)
            if summed_pubkey_bytes is None:
                return False, "Global ECDH share set but no eligible input public key found"
            A_sum = GE.from_bytes(summed_pubkey_bytes)

            valid, msg = validate_dleq_proof(A_sum, scan_key, ecdh_share, dleq_proof)
            if not valid:
                return False, f"Global DLEQ proof invalid: {msg}"

        # Verify the DLEQ proof of every per-input share present, whether or not the
        # output scripts are set yet: a Signer relies on them before it computes
        # the scripts. Coverage of every eligible input is only required once an
        # output script is set without a global share.
        require_coverage = scan_key_has_computed_output and not has_global_ecdh
        for i, input_map in enumerate(psbt.i):
            ecdh_share = input_map.get_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key)
            if not ecdh_share:
                # An input with no share has nothing to verify, and may not carry
                # its UTXO yet, so check its eligibility only if coverage is required
                if require_coverage and is_input_eligible(input_map):
                    return (
                        False,
                        f"Output script set but eligible input {i} missing ECDH share",
                    )
                continue
            if not is_input_eligible(input_map):
                continue

            dleq_proof = input_map.get_by_key(PSBT_IN_SP_DLEQ, scan_key)
            if not dleq_proof:
                return False, f"Input {i} ECDH share missing DLEQ proof"

            A = pubkey_from_eligible_input(input_map)
            if A is None:
                return (
                    False,
                    f"Input {i} missing public key for DLEQ verification",
                )

            valid, msg = validate_dleq_proof(A, scan_key, ecdh_share, dleq_proof)
            if not valid:
                return False, f"Input {i} DLEQ proof invalid: {msg}"
    return True, None


def validate_dleq_proof(
    A: GE,
    scan_key: bytes,
    ecdh_share: bytes,
    dleq_proof: bytes,
) -> Tuple[bool, str]:
    """
    Verify a DLEQ proof for silent payments

    Checks:
    - ECDH share and DLEQ proof lengths
    - Verify DLEQ proof correctness
    """
    if len(ecdh_share) != 33:
        return (
            False,
            f"Invalid ECDH share length: {len(ecdh_share)} bytes (expected 33)",
        )

    if len(dleq_proof) != 64:
        return (
            False,
            f"Invalid DLEQ proof length: {len(dleq_proof)} bytes (expected 64)",
        )

    B_scan = GE.from_bytes(scan_key)
    C_ecdh = GE.from_bytes(ecdh_share)

    # Verify DLEQ proof using BIP-374 reference
    result = dleq_verify_proof(A, B_scan, C_ecdh, dleq_proof)
    if not result:
        return False, "DLEQ proof verification failed"
    return True, None


def is_segwit_v2_or_later(script_pubkey: bytes) -> bool:
    """Return whether script_pubkey is a SegWit v2-v16 witness program."""
    return (
        4 <= len(script_pubkey) <= 42
        and 0x52 <= script_pubkey[0] <= 0x60  # OP_2 through OP_16
        and script_pubkey[1] == len(script_pubkey) - 2
    )


def validate_input_eligibility(psbt: PSBT) -> Tuple[bool, str]:
    """
    Validate input eligibility constraints for silent payments

    Checks:
    - No segwit v>1 inputs when SP outputs present
    - SIGHASH_ALL required when SP outputs present, for PSBT_IN_SIGHASH_TYPE and
      for the sighash byte of every signature
    - TX_MODIFIABLE Inputs/Outputs Modifiable flags are cleared once PSBT_OUT_SCRIPT
      is set for an SP output
    """
    # Check if SP outputs exist
    has_sp_outputs = any(PSBT_OUT_SP_V0_INFO in om for om in psbt.o)
    if not has_sp_outputs:
        return True, None

    # Check segwit version restrictions
    for i, input_map in enumerate(psbt.i):
        script = _script_pubkey_from_psbt_input(input_map)
        if script is not None and is_segwit_v2_or_later(script):
            return False, f"Input {i} uses segwit version > 1 with silent payments"

    # Check SIGHASH_ALL requirement - PSBT_IN_SIGHASH_TYPE is optional, but if set it must be SIGHASH_ALL when SP outputs are present
    # Taproot inputs may use SIGHASH_DEFAULT (0), which BIP-341 defines as equivalent to SIGHASH_ALL
    for i, input_map in enumerate(psbt.i):
        if PSBT_IN_SIGHASH_TYPE in input_map:
            sighash_type = int.from_bytes(input_map[PSBT_IN_SIGHASH_TYPE], "little")
            if sighash_type != 1 and not (  # SIGHASH_ALL
                sighash_type == 0  # SIGHASH_DEFAULT
                and _is_p2tr(_script_pubkey_from_psbt_input(input_map) or b"")
            ):
                return (
                    False,
                    f"Input {i} uses non-SIGHASH_ALL ({sighash_type}) with silent payments",
                )

    # A signature carries its own sighash type, which need not match
    # PSBT_IN_SIGHASH_TYPE or be declared at all
    missing_sp_script = any(
        PSBT_OUT_SP_V0_INFO in om and PSBT_OUT_SCRIPT not in om for om in psbt.o
    )
    for i, input_map in enumerate(psbt.i):
        signatures = input_signatures(input_map)
        if missing_sp_script and signatures:
            return False, f"Input {i} is signed before every silent payment output has PSBT_OUT_SCRIPT"
        for sig, is_schnorr in signatures:
            if not _signs_sighash_all(sig, is_schnorr):
                return (
                    False,
                    f"Input {i} has a non-SIGHASH_ALL signature with silent payments",
                )

    tx_modifiable = psbt.g.get(PSBT_GLOBAL_TX_MODIFIABLE)
    flags = tx_modifiable[0] if tx_modifiable else 0

    # Inputs/Outputs Modifiable must be False once PSBT_OUT_SCRIPT is set for an SP output
    if flags & 0x03:
        for i, output_map in enumerate(psbt.o):
            if (
                PSBT_OUT_SP_V0_INFO in output_map
                and len(output_map.get(PSBT_OUT_SCRIPT, b"")) > 0
            ):
                return (
                    False,
                    f"Output {i} has PSBT_OUT_SCRIPT set for silent payments output but "
                    "PSBT_GLOBAL_TX_MODIFIABLE Inputs/Outputs Modifiable flags not cleared",
                )
    return True, None


def _signs_sighash_all(sig: bytes, is_schnorr: bool) -> bool:
    """True if a signature uses SIGHASH_ALL, or SIGHASH_DEFAULT for a BIP-340
    signature, which a 64-byte signature encodes by omitting the type byte"""
    if is_schnorr and len(sig) == 64:
        return True
    return len(sig) > 0 and sig[-1] == 1


def validate_output_scripts(psbt: PSBT) -> Tuple[bool, str]:
    """
    Validate computed output scripts match silent payment derivation

    Checks:
    - For each SP output with PSBT_OUT_SCRIPT set, recomputes the expected P2TR
      script from the ECDH share and input public keys and verifies it matches
    - k values are tracked per scan key and incremented for each SP output sharing
      the same scan key (outputs with different scan keys use independent k counters)
    """
    # Build outpoints list
    outpoints = []
    for input_map in psbt.i:
        if PSBT_IN_PREVIOUS_TXID in input_map and PSBT_IN_OUTPUT_INDEX in input_map:
            output_index_bytes = input_map.get(PSBT_IN_OUTPUT_INDEX)
            txid_int = int.from_bytes(input_map[PSBT_IN_PREVIOUS_TXID], "little")
            output_index = struct.unpack("<I", output_index_bytes)[0]
            outpoints.append(COutPoint(txid_int, output_index))

    # Silent payment codes sorted lexicographically, ties broken by output index
    sp_outputs = [
        (output_map[PSBT_OUT_SP_V0_INFO], output_idx, output_map)
        for output_idx, output_map in enumerate(psbt.o)
        if PSBT_OUT_SP_V0_INFO in output_map
    ]
    sp_outputs.sort(key=lambda entry: (entry[0], entry[1]))

    # Track k values per scan key
    scan_key_k_values = {}

    for sp_info, output_idx, output_map in sp_outputs:
        scan_pubkey_bytes = sp_info[:33]
        spend_pubkey_bytes = sp_info[33:]

        k = scan_key_k_values.get(scan_pubkey_bytes, 0)

        # Get ECDH share and summed pubkey
        ecdh_share_bytes, summed_pubkey_bytes = collect_input_ecdh_and_pubkey(
            psbt, scan_pubkey_bytes
        )

        if ecdh_share_bytes and summed_pubkey_bytes and outpoints:
            computed_script = compute_silent_payment_output_script(
                outpoints, summed_pubkey_bytes, ecdh_share_bytes, spend_pubkey_bytes, k
            )

            if PSBT_OUT_SCRIPT in output_map:
                actual_script = output_map[PSBT_OUT_SCRIPT]
                if actual_script != computed_script:
                    return (
                        False,
                        f"Output {output_idx} script doesn't match silent payments derivation",
                    )

            scan_key_k_values[scan_pubkey_bytes] = k + 1
        elif PSBT_OUT_SCRIPT in output_map:
            return (
                False,
                f"Output {output_idx} has PSBT_OUT_SCRIPT but missing ECDH share or input pubkeys",
            )
    return True, None
