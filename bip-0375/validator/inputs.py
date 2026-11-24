#!/usr/bin/env python3
"""
PSBT input utility functions
"""

import struct
from typing import List, Optional, Tuple

from deps.bitcoin_test.messages import CTransaction, CTxOut, from_binary, hash160
from deps.bitcoin_test.psbt import (
    PSBT,
    PSBT_IN_BIP32_DERIVATION,
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_TAP_INTERNAL_KEY,
    PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_TAP_SCRIPT_SIG,
    PSBT_IN_WITNESS_UTXO,
)
from secp256k1lab.secp256k1 import GE

from .psbt_bip375 import (
    BIP375PSBTMap,
    PSBT_GLOBAL_SP_ECDH_SHARE,
    PSBT_IN_SP_ECDH_SHARE,
    ValidationError,
)


def collect_input_ecdh_and_pubkey(
    psbt: PSBT, scan_key: bytes
) -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Collect combined ECDH share and summed pubkey for a scan key.

    Uses the global ECDH share if set, otherwise the per-input shares.
    Returns (ecdh_share_bytes, summed_pubkey_bytes) or (None, None). Raises
    ValidationError when the eligible input pubkeys cannot be summed.
    """
    # Check for global ECDH share
    summed_pubkey = None
    ecdh_share = psbt.g.get_by_key(PSBT_GLOBAL_SP_ECDH_SHARE, scan_key)
    if ecdh_share:
        for i, input_map in enumerate(psbt.i):
            if not is_input_eligible(input_map, i):
                continue
            pubkey = pubkey_from_eligible_input(input_map, i)
            summed_pubkey = pubkey if summed_pubkey is None else summed_pubkey + pubkey
        if summed_pubkey is None:
            raise ValidationError(
                "Global ECDH share set but no eligible input public key found"
            )
        if summed_pubkey.infinity:
            raise ValidationError(
                "Global eligible input public keys sum to the point at infinity"
            )
        return ecdh_share, summed_pubkey.to_bytes_compressed()

    # Check for per-input ECDH shares
    combined_ecdh = None
    for i, input_map in enumerate(psbt.i):
        input_ecdh = input_map.get_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key)
        if input_ecdh:
            if not is_input_eligible(input_map, i):
                continue # skip ineligible inputs
            ecdh_point = GE.from_bytes(input_ecdh)
            combined_ecdh = (
                ecdh_point if combined_ecdh is None else combined_ecdh + ecdh_point
            )
            pubkey = pubkey_from_eligible_input(input_map, i)
            summed_pubkey = pubkey if summed_pubkey is None else summed_pubkey + pubkey

    if combined_ecdh is not None and summed_pubkey is not None:
        if summed_pubkey.infinity:
            raise ValidationError(
                "Eligible input public keys sum to the point at infinity"
            )
        return combined_ecdh.to_bytes_compressed(), summed_pubkey.to_bytes_compressed()
    return None, None


def pubkey_from_eligible_input(input_map: BIP375PSBTMap, index: int) -> Optional[GE]:
    """
    Extract the public key from a PSBT input map if eligible for silent payments

    Returns a GE point (public key), or None if the input is not eligible.
    Raises ValidationError for an eligible input with no usable key. index
    names the input in errors.
    """
    if not is_input_eligible(input_map, index):
        return None

    # Try BIP32 derivation first (key_data is the pubkey)
    derivations = input_map.get_all_by_type(PSBT_IN_BIP32_DERIVATION)
    if derivations:
        pubkey, _ = derivations[0]
        if len(pubkey) == 33:
            return _public_key(pubkey, index)

    # Try PSBT_IN_WITNESS_UTXO for P2TR inputs
    spk = parse_witness_utxo(input_map[PSBT_IN_WITNESS_UTXO])
    if spk and is_p2tr(spk):
        return _public_key(bytes([0x02]) + spk[2:34], index)
    raise ValidationError(f"Input {index} has no PSBT_IN_BIP32_DERIVATION")


def _public_key(pubkey: bytes, index: int) -> GE:
    """Parse an input's public key, which must be a valid point"""
    try:
        return GE.from_bytes(pubkey)
    except ValueError:
        raise ValidationError(f"Input {index} public key is not a valid point")


# ============================================================================
# scriptPubKey helpers
# ============================================================================


def script_pubkey_from_psbt_input(
    input_map: BIP375PSBTMap, index: int
) -> Optional[bytes]:
    """Extract scriptPubKey from PSBT input fields. index names the input in errors."""
    script_pubkey = None

    # Try WITNESS_UTXO first
    if PSBT_IN_WITNESS_UTXO in input_map:
        script_pubkey = parse_witness_utxo(input_map[PSBT_IN_WITNESS_UTXO])

    # Try NON_WITNESS_UTXO for legacy inputs
    elif PSBT_IN_NON_WITNESS_UTXO in input_map:
        non_witness_utxo = input_map[PSBT_IN_NON_WITNESS_UTXO]
        # Get the output index from PSBT_IN_OUTPUT_INDEX field
        if PSBT_IN_OUTPUT_INDEX in input_map:
            output_index_bytes = input_map[PSBT_IN_OUTPUT_INDEX]
            if len(output_index_bytes) == 4:
                output_index = struct.unpack("<I", output_index_bytes)[0]
                script_pubkey = _parse_non_witness_utxo(
                    non_witness_utxo, output_index, index
                )
    return script_pubkey


def parse_witness_utxo(witness_utxo: bytes) -> bytes:
    """Extract scriptPubKey from witness_utxo"""
    utxo = from_binary(CTxOut, witness_utxo)
    return utxo.scriptPubKey


def _parse_non_witness_utxo(
    non_witness_utxo: bytes, output_index: int, index: int
) -> bytes:
    """Extract scriptPubKey from non_witness_utxo"""
    tx = from_binary(CTransaction, non_witness_utxo)
    if output_index >= len(tx.vout):
        raise ValidationError(f"Input {index} has an invalid output index")
    return tx.vout[output_index].scriptPubKey


# ============================================================================
# Input eligibility helpers
# ============================================================================


def is_input_eligible(input_map: BIP375PSBTMap, index: int) -> bool:
    """
    Check if input is eligible for silent payments

    Raises ValidationError, naming the input by index, when eligibility cannot
    be determined.
    """
    script_pubkey = script_pubkey_from_psbt_input(input_map, index)
    if script_pubkey is None:
        raise ValidationError(f"Input {index} scriptPubKey could not be extracted")

    if not _has_eligible_script_type(script_pubkey):
        return False

    if is_p2pkh(script_pubkey):
        # BIP-352 skips a P2PKH input whose public key is uncompressed
        for pubkey, _ in input_map.get_all_by_type(PSBT_IN_BIP32_DERIVATION):
            if len(pubkey) == 65 and script_pubkey == _p2pkh_script(hash160(pubkey)):
                return False

    NUMS_H = bytes.fromhex(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    )
    if is_p2tr(script_pubkey):
        tap_internal_key = input_map.get(PSBT_IN_TAP_INTERNAL_KEY)
        if tap_internal_key == NUMS_H:
            return False

    if is_p2sh(script_pubkey):
        if PSBT_IN_REDEEM_SCRIPT in input_map:
            redeem_script = input_map[PSBT_IN_REDEEM_SCRIPT]
            if script_pubkey != _p2sh_script(hash160(redeem_script)):
                raise ValidationError(
                    f"Input {index} P2SH redeem script does not match scriptPubKey"
                )
            if not is_p2wpkh(redeem_script):
                return False
        else:
            raise ValidationError(f"Input {index} is P2SH and missing redeem script")
    return True


def _has_eligible_script_type(script_pubkey: bytes) -> bool:
    """True if scriptPubKey is eligible for silent payments"""
    return (
        is_p2pkh(script_pubkey)
        or is_p2wpkh(script_pubkey)
        or is_p2tr(script_pubkey)
        or is_p2sh(script_pubkey)
    )


def is_p2tr(script_pubkey: bytes) -> bool:
    return len(script_pubkey) == 34 and script_pubkey == _p2tr_script(script_pubkey[2:])


def is_p2wpkh(script_pubkey: bytes) -> bool:
    return len(script_pubkey) == 22 and script_pubkey == _p2wpkh_script(
        script_pubkey[2:]
    )


def is_p2sh(script_pubkey: bytes) -> bool:
    return len(script_pubkey) == 23 and script_pubkey == _p2sh_script(
        script_pubkey[2:22]
    )


def is_p2pkh(script_pubkey: bytes) -> bool:
    return len(script_pubkey) == 25 and script_pubkey == _p2pkh_script(
        script_pubkey[3:23]
    )


def _p2tr_script(output_key: bytes) -> bytes:
    """OP_1 <32-byte x-only output key>"""
    return bytes([0x51, 0x20]) + output_key


def _p2pkh_script(pubkey_hash: bytes) -> bytes:
    """OP_DUP OP_HASH160 <pubkey hash> OP_EQUALVERIFY OP_CHECKSIG"""
    return bytes([0x76, 0xA9, 0x14]) + pubkey_hash + bytes([0x88, 0xAC])


def _p2wpkh_script(pubkey_hash: bytes) -> bytes:
    """OP_0 <pubkey hash>"""
    return bytes([0x00, 0x14]) + pubkey_hash


def _p2sh_script(script_hash: bytes) -> bytes:
    """OP_HASH160 <script hash> OP_EQUAL"""
    return bytes([0xA9, 0x14]) + script_hash + bytes([0x87])


# ============================================================================
# Signature helpers
# ============================================================================


def input_signatures(input_map: BIP375PSBTMap) -> List[Tuple[bytes, bool]]:
    """Every signature an input carries, as (signature, is_schnorr) tuples"""
    sigs = [(sig, False) for _, sig in input_map.get_all_by_type(PSBT_IN_PARTIAL_SIG)]
    if PSBT_IN_TAP_KEY_SIG in input_map:
        sigs.append((input_map[PSBT_IN_TAP_KEY_SIG], True))
    sigs += [
        (sig, True) for _, sig in input_map.get_all_by_type(PSBT_IN_TAP_SCRIPT_SIG)
    ]
    return sigs
