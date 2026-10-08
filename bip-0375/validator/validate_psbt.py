#!/usr/bin/env python3
"""
Validates PSBTs according to BIP-375 rules

Provides independent checks for PSBT structure, ECDH share coverage,
input eligibility, and output script correctness.
"""

import struct
from typing import Iterator, Optional, Tuple

from deps.bitcoin_test.psbt import (
    PSBT,
    PSBT_GLOBAL_TX_MODIFIABLE,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_WITNESS_UTXO,
    PSBT_OUT_SCRIPT,
)
from deps.dleq import dleq_verify_proof
from secp256k1lab.secp256k1 import GE

from .bip352_crypto import compute_silent_payment_output_script
from .inputs import (
    build_outpoints,
    collect_input_ecdh_and_pubkey,
    is_input_eligible,
    is_p2tr,
    parse_witness_utxo,
    pubkey_from_eligible_input,
    script_pubkey_from_psbt_input,
    sp_scan_keys,
)
from .psbt_bip375 import (
    BIP375PSBT,
    BIP375PSBTMap,
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
    - ECDH shares must be 33 bytes
    - DLEQ proofs must be 64 bytes
    """
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

    # Validate ECDH share lengths (global and per-input)
    global_ecdh_shares = psbt.g.get_all_by_type(PSBT_GLOBAL_SP_ECDH_SHARE)
    for _, ecdh_share in global_ecdh_shares:
        if len(ecdh_share) != 33:
            return (
                False,
                f"Global ECDH share has wrong length ({len(ecdh_share)} bytes, expected 33)",
            )

    for i, input_map in enumerate(psbt.i):
        input_ecdh_shares = input_map.get_all_by_type(PSBT_IN_SP_ECDH_SHARE)
        for _, ecdh_share in input_ecdh_shares:
            if len(ecdh_share) != 33:
                return (
                    False,
                    f"Input {i} ECDH share has wrong length ({len(ecdh_share)} bytes, expected 33)",
                )

    # Validate DLEQ proof lengths (global and per-input)
    global_dleq_proofs = psbt.g.get_all_by_type(PSBT_GLOBAL_SP_DLEQ)
    for _, dleq_proof in global_dleq_proofs:
        if len(dleq_proof) != 64:
            return (
                False,
                f"Global DLEQ proof has wrong length ({len(dleq_proof)} bytes, expected 64)",
            )

    for i, input_map in enumerate(psbt.i):
        input_dleq_proofs = input_map.get_all_by_type(PSBT_IN_SP_DLEQ)
        for _, dleq_proof in input_dleq_proofs:
            if len(dleq_proof) != 64:
                return (
                    False,
                    f"Input {i} DLEQ proof has wrong length ({len(dleq_proof)} bytes, expected 64)",
                )

    return True, None


def validate_ecdh_coverage(psbt: PSBT) -> Tuple[bool, str]:
    """
    Validate ECDH share coverage and DLEQ proof correctness

    Checks:
    - Verify ECDH share coverage for each scan key associated with SP outputs
    - Every ECDH share must have a corresponding DLEQ proof
    - If PSBT_OUT_SCRIPT is set, all eligible inputs must have ECDH coverage
    - DLEQ proofs must verify correctly
    """
    scan_keys = sp_scan_keys(psbt)

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
    - SIGHASH_ALL required when SP outputs present
    - TX_MODIFIABLE Inputs/Outputs Modifiable flags are cleared once PSBT_OUT_SCRIPT
      is set for an SP output
    """
    # Check if SP outputs exist
    has_sp_outputs = any(PSBT_OUT_SP_V0_INFO in om for om in psbt.o)
    if not has_sp_outputs:
        return True, None

    # Check segwit version restrictions
    for i, input_map in enumerate(psbt.i):
        if PSBT_IN_WITNESS_UTXO in input_map:
            witness_utxo = input_map[PSBT_IN_WITNESS_UTXO]
            script = parse_witness_utxo(witness_utxo)
            if is_segwit_v2_or_later(script):
                return False, f"Input {i} uses segwit version > 1 with silent payments"

    # Check SIGHASH_ALL requirement - PSBT_IN_SIGHASH_TYPE is optional, but if set it must be SIGHASH_ALL when SP outputs are present
    # Taproot inputs may use SIGHASH_DEFAULT (0), which BIP-341 defines as equivalent to SIGHASH_ALL
    for i, input_map in enumerate(psbt.i):
        if PSBT_IN_SIGHASH_TYPE in input_map:
            sighash = input_map[PSBT_IN_SIGHASH_TYPE]
            if len(sighash) >= 4:
                sighash_type = struct.unpack("<I", sighash[:4])[0]
                if sighash_type != 1 and not (  # SIGHASH_ALL
                    sighash_type == 0  # SIGHASH_DEFAULT
                    and is_p2tr(script_pubkey_from_psbt_input(input_map) or b"")
                ):
                    return (
                        False,
                        f"Input {i} uses non-SIGHASH_ALL ({sighash_type}) with silent payments",
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


def derive_sp_output_scripts(
    psbt: PSBT,
) -> Iterator[Tuple[int, BIP375PSBTMap, Optional[bytes]]]:
    """Yield (output_idx, output_map, computed_script) for every silent payment output.

    k is assigned per scan key in (sp_info, output_idx) sorted order, so the
    Signer that sets the scripts and the checks that verify them agree.
    computed_script is None when the ECDH share or input pubkeys are unavailable.
    """
    outpoints = build_outpoints(psbt)

    sp_outputs = [
        (output_map[PSBT_OUT_SP_V0_INFO], output_idx, output_map)
        for output_idx, output_map in enumerate(psbt.o)
        if PSBT_OUT_SP_V0_INFO in output_map
    ]
    sp_outputs.sort(key=lambda entry: (entry[0], entry[1]))

    scan_key_k_values = {}
    for sp_info, output_idx, output_map in sp_outputs:
        scan_key = sp_info[:33]
        spend_key = sp_info[33:]
        k = scan_key_k_values.get(scan_key, 0)

        ecdh_share_bytes, summed_pubkey_bytes = collect_input_ecdh_and_pubkey(
            psbt, scan_key
        )

        if ecdh_share_bytes and summed_pubkey_bytes and outpoints:
            script = compute_silent_payment_output_script(
                outpoints, summed_pubkey_bytes, ecdh_share_bytes, spend_key, k
            )
            scan_key_k_values[scan_key] = k + 1
            yield output_idx, output_map, script
        else:
            yield output_idx, output_map, None


def validate_output_scripts(psbt: PSBT) -> Tuple[bool, str]:
    """
    Validate computed output scripts match silent payment derivation

    Checks:
    - For each SP output with PSBT_OUT_SCRIPT set, recomputes the expected P2TR
      script from the ECDH share and input public keys and verifies it matches
    - k values are tracked per scan key and incremented for each SP output sharing
      the same scan key (outputs with different scan keys use independent k counters)
    """
    for output_idx, output_map, computed_script in derive_sp_output_scripts(psbt):
        if computed_script is None:
            if PSBT_OUT_SCRIPT in output_map:
                return (
                    False,
                    f"Output {output_idx} has PSBT_OUT_SCRIPT but missing ECDH share or input pubkeys",
                )
        elif PSBT_OUT_SCRIPT in output_map and output_map[PSBT_OUT_SCRIPT] != computed_script:
            return (
                False,
                f"Output {output_idx} script doesn't match silent payments derivation",
            )
    return True, None


CHECK_FUNCTIONS = {
    "psbt_structure": validate_psbt_structure,
    "ecdh_coverage": validate_ecdh_coverage,
    "input_eligibility": validate_input_eligibility,
    "output_scripts": validate_output_scripts,
}


def run_checks(
    psbt: PSBT, checks: Optional[list[str]] = None, debug: bool = False
) -> Tuple[bool, str, Optional[str]]:
    """Run the named checks (every check by default) in order on a parsed PSBT.

    Returns (is_valid, message, failing_check): failing_check names the check
    that rejected the PSBT, or None if every check passed.
    """
    for check_name in checks if checks is not None else CHECK_FUNCTIONS:
        if check_name not in CHECK_FUNCTIONS:
            return False, f"Unknown check: {check_name}", check_name

        is_valid, msg = CHECK_FUNCTIONS[check_name](psbt)
        if debug:
            msg = f"{check_name.upper()}: {msg}" if msg else msg

        if not is_valid:
            return False, msg, check_name

    return True, "All checks passed", None


def validate_bip375_psbt(
    psbt_data: str, checks: Optional[list[str]] = None, debug: bool = False
) -> Tuple[bool, str, Optional[str]]:
    """Performs sequential validation of a base64 PSBT against BIP-375 rules.
    See run_checks for the return value."""
    return run_checks(BIP375PSBT.from_base64(psbt_data), checks, debug)
