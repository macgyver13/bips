#!/usr/bin/env python3
"""
BIP-375 Reference Implementation - PSBT v2 Workflow Functions

Implements the PSBT v2 role workflow for Silent Payments:
  Creator → Constructor → Updater → Signer → Finalizer → Extractor

This module provides reference functions for each role in the PSBT workflow.
"""

import secrets
from io import BytesIO
from enum import Enum
from typing import Dict, List, Tuple

from bitcoin_test.psbt import (
    PSBT_GLOBAL_VERSION,
    PSBT_GLOBAL_TX_VERSION,
    PSBT_GLOBAL_INPUT_COUNT,
    PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_TX_MODIFIABLE,
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_SEQUENCE,
    PSBT_IN_WITNESS_UTXO,
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_BIP32_DERIVATION,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_OUT_AMOUNT,
    PSBT_OUT_SCRIPT,
    PSBT_OUT_BIP32_DERIVATION,
)
from bitcoin_test.transaction import CTransaction, CTxIn, CTxOut, COutPoint
from bitcoin_test.utils import (
    is_p2wpkh,
    is_p2tr,
    from_binary,
    deser_string_vector,
)
from bitcoin_test.signing import ECKey
from bitcoin_test.messages import CTxInWitness
from bitcoin_test.sighash import (
    SegwitV0SignatureHash,
    TaprootSignatureHash,
    make_p2wpkh_script_code,
    SIGHASH_ALL,
    SIGHASH_DEFAULT,
)
from dleq import dleq_generate_proof
from validator.inputs import sp_scan_keys, scan_key_is_covered
from validator.psbt_bip375 import (
    BIP375PSBT as PSBT,
    BIP375PSBTMap as PSBTMap,
    PSBT_GLOBAL_SP_ECDH_SHARE,
    PSBT_GLOBAL_SP_DLEQ,
    PSBT_IN_SP_ECDH_SHARE,
    PSBT_IN_SP_DLEQ,
    PSBT_OUT_SP_V0_INFO,
    PSBT_OUT_SP_V0_LABEL,
)
from secp256k1lab.secp256k1 import GE
from secp256k1lab.bip340 import schnorr_sign
from validator.bip352_crypto import derive_sp_output_scripts
from validator.validate_psbt import validate_ecdh_coverage, validate_output_scripts

class PSBTState(Enum):
    # Member name = the role that produced the PSBT; value = the task verb the
    # workflow vectors use for that step, so PSBTState(task) maps one to the other.
    CREATOR = "create"
    CONSTRUCTOR = "construct"
    UPDATER = "update"
    SIGNER = "sign"
    FINALIZER = "finalize"
    EXTRACTOR = "extract"

class InvalidStateTransitionError(Exception):
    """Raised when a PSBT role function is called on a PSBT in an invalid state."""
    pass

def detect_psbt_step(psbt: PSBT) -> PSBTState:
    """Detect the role that last touched this PSBT.

    Roles only add fields, so the current step is the latest role whose marker
    field is present; check newest-first.

    EXTRACTOR is never returned: the Extractor emits a transaction and leaves the
    PSBT untouched, so it is indistinguishable from FINALIZER.
    """
    if len(psbt.i) < 1 and len(psbt.o) < 1:
        return PSBTState.CREATOR

    if all(PSBT_IN_FINAL_SCRIPTWITNESS in inp for inp in psbt.i) and psbt.i:
        return PSBTState.FINALIZER

    # The Signer contributes the ECDH shares, so a share marks the Signer step even
    # before any signature exists: a party holding only some of the inputs must wait
    # for full share coverage before it may sign.
    has_ecdh = psbt.g.get_all_by_type(PSBT_GLOBAL_SP_ECDH_SHARE) or any(inp.get_all_by_type(PSBT_IN_SP_ECDH_SHARE) for inp in psbt.i)
    has_sigs = any(inp.get_all_by_type(PSBT_IN_PARTIAL_SIG) or PSBT_IN_TAP_KEY_SIG in inp for inp in psbt.i)
    if has_ecdh or has_sigs:
        return PSBTState.SIGNER

    has_updates = any(
        PSBT_IN_WITNESS_UTXO in inp
        or PSBT_IN_NON_WITNESS_UTXO in inp
        or inp.get_all_by_type(PSBT_IN_BIP32_DERIVATION)
        for inp in psbt.i
    )
    if has_updates:
        return PSBTState.UPDATER

    return PSBTState.CONSTRUCTOR


# =============================================================================
# Role 1: Creator
# =============================================================================


def create_psbt(tx_version: int = 2) -> PSBT:
    """
    Creator role: Initialize an empty PSBT v2 structure.

    Args:
        tx_version: Transaction version (default 2)

    Returns:
        Empty PSBT v2 with global fields set
    """
    psbt = PSBT()

    # Set PSBT version
    psbt.g[PSBT_GLOBAL_VERSION] = _serialize_psbt_uint32(2)

    # Set transaction version
    psbt.g[PSBT_GLOBAL_TX_VERSION] = _serialize_psbt_uint32(tx_version)

    # Set modifiable flags (inputs and outputs modifiable)
    # Bit 0: Inputs Modifiable, Bit 1: Outputs Modifiable
    psbt.g[PSBT_GLOBAL_TX_MODIFIABLE] = bytes([0x03])

    # Initialize counts to 0
    psbt.g[PSBT_GLOBAL_INPUT_COUNT] = bytes([0])
    psbt.g[PSBT_GLOBAL_OUTPUT_COUNT] = bytes([0])

    return psbt


# =============================================================================
# Role 2: Constructor
# =============================================================================


def construct_sp_psbt(
    psbt: PSBT,
    inputs: List[Dict],
    sp_outputs: List[Dict],
    regular_outputs: List[Dict] = None,
) -> PSBT:
    """
    Constructor role: Add inputs and outputs to the PSBT.

    Args:
        psbt: PSBT from Creator
        inputs: List of input dicts with keys:
            - txid: bytes (32 bytes, internal byte order)
            - vout: int
            - sequence: int (optional, default 0xFFFFFFFD)
        sp_outputs: List of silent payment output dicts with keys:
            - scan_key: bytes (33-byte compressed pubkey)
            - spend_key: bytes (33-byte compressed pubkey)
            - amount: int (satoshis)
            - label: int (optional, 4-byte label)
        regular_outputs: List of regular output dicts with keys:
            - script: bytes (scriptPubKey)
            - amount: int (satoshis)

    Returns:
        PSBT with inputs and outputs added
    """
    if detect_psbt_step(psbt) != PSBTState.CREATOR:
        raise InvalidStateTransitionError("PSBT must be empty to construct inputs and outputs")

    if regular_outputs is None:
        regular_outputs = []

    # Add inputs
    for inp in inputs:
        input_map = PSBTMap()
        input_map[PSBT_IN_PREVIOUS_TXID] = inp["txid"]
        input_map[PSBT_IN_OUTPUT_INDEX] = _serialize_psbt_uint32(inp["vout"])
        sequence = inp.get("sequence", 0xFFFFFFFD)
        input_map[PSBT_IN_SEQUENCE] = _serialize_psbt_uint32(sequence)
        psbt.i.append(input_map)

    # Add silent payment outputs
    for sp_out in sp_outputs:
        output_map = PSBTMap()
        # SP_V0_INFO = scan_key (33 bytes) + spend_key (33 bytes)
        sp_info = sp_out["scan_key"] + sp_out["spend_key"]
        output_map[PSBT_OUT_SP_V0_INFO] = sp_info
        output_map[PSBT_OUT_AMOUNT] = _serialize_psbt_uint64(sp_out["amount"])

        # Optional label
        if "label" in sp_out:
            output_map[PSBT_OUT_SP_V0_LABEL] = _serialize_psbt_uint32(sp_out["label"])

        psbt.o.append(output_map)

    # Add regular outputs
    for reg_out in regular_outputs:
        output_map = PSBTMap()
        output_map[PSBT_OUT_SCRIPT] = reg_out["script"]
        output_map[PSBT_OUT_AMOUNT] = _serialize_psbt_uint64(reg_out["amount"])
        psbt.o.append(output_map)

    # Update counts
    psbt.g[PSBT_GLOBAL_INPUT_COUNT] = bytes([len(psbt.i)])
    psbt.g[PSBT_GLOBAL_OUTPUT_COUNT] = bytes([len(psbt.o)])

    return psbt


# =============================================================================
# Role 3: Updater
# =============================================================================


def update_sp_psbt(
    psbt: PSBT,
    input_utxos: List[Dict],
    input_derivations: List[Dict] = None,
    output_derivations: List[Dict] = None,
) -> PSBT:
    """
    Updater role: Add UTXO info and BIP32 derivations.

    The Updater is not assumed to hold any private key; the ECDH shares and DLEQ
    proofs are Signer material (see sign_sp_psbt).

    Args:
        psbt: PSBT from Constructor
        input_utxos: List of UTXO dicts per input:
            - witness_utxo: bytes (serialized output) OR
            - non_witness_utxo: bytes (serialized full transaction)
        input_derivations: List of derivation dicts per input (optional):
            - pubkey: bytes (33-byte compressed pubkey)
            - fingerprint: bytes (4 bytes, can be zeros for privacy)
            - path: List[int] (derivation path indices)
        output_derivations: List of derivation dicts per SP output (optional):
            - scan_pubkey: bytes
            - scan_fingerprint: bytes
            - scan_path: List[int]
            - spend_pubkey: bytes
            - spend_fingerprint: bytes
            - spend_path: List[int]

    Returns:
        PSBT with UTXO info and derivations
    """
    # Allow re-entry from UPDATED so multiple parties can each add their
    # UTXO and derivation data across successive update calls (multi-party).
    if detect_psbt_step(psbt) not in (PSBTState.CONSTRUCTOR, PSBTState.UPDATER):
        raise InvalidStateTransitionError("PSBT must be in 'constructed' or 'updated' state to update")

    if input_derivations is None:
        input_derivations = [None] * len(psbt.i)
    if output_derivations is None:
        output_derivations = [None] * len(psbt.o)

    # Add UTXO info and derivations for each input
    for i, (input_map, utxo_info) in enumerate(zip(psbt.i, input_utxos)):
        if "witness_utxo" in utxo_info:
            input_map[PSBT_IN_WITNESS_UTXO] = utxo_info["witness_utxo"]
        elif "non_witness_utxo" in utxo_info:
            input_map[PSBT_IN_NON_WITNESS_UTXO] = utxo_info["non_witness_utxo"]

        # Add BIP32 derivation if provided
        if i < len(input_derivations) and input_derivations[i] is not None:
            deriv = input_derivations[i]
            pubkey = deriv["pubkey"]
            fingerprint = deriv.get("fingerprint", bytes(4))
            path = deriv.get("path", [])
            # Value = fingerprint (4 bytes) + path (4 bytes each, little-endian)
            value = fingerprint + b"".join(_serialize_psbt_uint32(idx) for idx in path)
            input_map.set_by_key(PSBT_IN_BIP32_DERIVATION, pubkey, value)

    # Add BIP32 derivations for SP outputs (for change verification)
    for i, output_map in enumerate(psbt.o):
        if PSBT_OUT_SP_V0_INFO not in output_map:
            continue
        if i >= len(output_derivations) or output_derivations[i] is None:
            continue

        deriv = output_derivations[i]

        # Scan key derivation
        if "scan_pubkey" in deriv:
            scan_fp = deriv.get("scan_fingerprint", bytes(4))
            scan_path = deriv.get("scan_path", [])
            scan_value = scan_fp + b"".join(_serialize_psbt_uint32(idx) for idx in scan_path)
            output_map.set_by_key(
                PSBT_OUT_BIP32_DERIVATION, deriv["scan_pubkey"], scan_value
            )

        # Spend key derivation
        if "spend_pubkey" in deriv:
            spend_fp = deriv.get("spend_fingerprint", bytes(4))
            spend_path = deriv.get("spend_path", [])
            spend_value = spend_fp + b"".join(
                _serialize_psbt_uint32(idx) for idx in spend_path
            )
            output_map.set_by_key(
                PSBT_OUT_BIP32_DERIVATION, deriv["spend_pubkey"], spend_value
            )

    return psbt


def _create_ecdh_share_and_proof(a: int, scan_key_bytes: bytes) -> tuple[bytes, bytes]:
    """Internal helper to generate ECDH share and DLEQ proof."""
    B_scan = GE.from_bytes(scan_key_bytes)
    r = secrets.token_bytes(32)
    proof = dleq_generate_proof(a, B_scan, r)
    if proof is None:
        raise ValueError("Failed to generate DLEQ proof")

    C_ecdh = a * B_scan
    return C_ecdh.to_bytes_compressed(), proof


# =============================================================================
# Silent payment output scripts (a Signer duty, see sign_sp_psbt)
# =============================================================================


def _compute_sp_output_scripts(psbt: PSBT) -> PSBT:
    """
    Compute and set the output scripts for SP outputs, then clear the modifiable
    flags. The caller must have established that every eligible input carries an
    ECDH share for every scan key (see _has_full_ecdh_coverage).

    Returns:
        PSBT with PSBT_OUT_SCRIPT set for SP outputs
    """
    for _output_idx, output_map, script in derive_sp_output_scripts(psbt):
        if script is None:
            raise ValueError(
                "Cannot compute SP output script: missing ECDH share or input pubkeys"
            )
        output_map[PSBT_OUT_SCRIPT] = script

    # Clear modifiable flag (no more modifications allowed)
    psbt.g[PSBT_GLOBAL_TX_MODIFIABLE] = bytes([0x00])

    return psbt


# =============================================================================
# Role 4: Signer
# =============================================================================


def _has_full_ecdh_coverage(psbt: PSBT) -> bool:
    """True when every scan key is covered by a global share, or by a per-input
    share on every eligible input. Only then can the SP output scripts be computed."""
    return all(scan_key_is_covered(psbt, sk) for sk in sp_scan_keys(psbt))


def _add_ecdh_shares(psbt: PSBT, input_private_keys: List[Tuple[int, bytes]]) -> None:
    """Add this party's ECDH shares and DLEQ proofs.

    A party holding the private key for every input publishes a single global share
    over the summed keys; a party holding only some publishes per-input shares, which
    combine with the other parties' across successive Signer calls. Shares already in
    the PSBT are left alone so another party's DLEQ proof is never overwritten.
    """
    scan_keys = sp_scan_keys(psbt)
    if not scan_keys or not input_private_keys:
        return

    privkeys = [int.from_bytes(pk, "big") for _, pk in input_private_keys]

    if len(input_private_keys) == len(psbt.i):
        a_sum = sum(privkeys) % GE.ORDER
        for scan_key in scan_keys:
            if psbt.g.get_by_key(PSBT_GLOBAL_SP_ECDH_SHARE, scan_key):
                continue
            ecdh_share, proof = _create_ecdh_share_and_proof(a_sum, scan_key)
            psbt.g.set_by_key(PSBT_GLOBAL_SP_ECDH_SHARE, scan_key, ecdh_share)
            psbt.g.set_by_key(PSBT_GLOBAL_SP_DLEQ, scan_key, proof)
        return

    for (idx, _), a in zip(input_private_keys, privkeys):
        input_map = psbt.i[idx]
        for scan_key in scan_keys:
            if input_map.get_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key):
                continue
            ecdh_share, proof = _create_ecdh_share_and_proof(a, scan_key)
            input_map.set_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key, ecdh_share)
            input_map.set_by_key(PSBT_IN_SP_DLEQ, scan_key, proof)


def sign_sp_psbt(
    psbt: PSBT,
    input_private_keys: List[Tuple[int, bytes]],
    input_indices: List[int] = None,
) -> PSBT:
    """
    Signer role: Contribute ECDH shares, compute the SP output scripts once every
    eligible input is covered, and sign.

    A Signer that cannot yet compute the output scripts (another party's share is
    still missing) contributes its share and returns unsigned: BIP-375 forbids
    signing before the output scripts commit. That party signs on a later call,
    once the last Signer has set the scripts.

    Args:
        psbt: PSBT from the Updater, or from a previous Signer
        input_private_keys: List of (index, private_key_bytes) tuples for the inputs
            whose key this party holds
        input_indices: Indices of inputs to sign (if None, sign all with matching keys)

    Returns:
        PSBT with ECDH shares added, and signatures if the output scripts are set

    Note: Multi-party signing is supported by calling this function multiple
    times with different private keys - the PSBT can be passed between parties.
    """
    current_state = detect_psbt_step(psbt)
    if current_state not in (PSBTState.UPDATER, PSBTState.SIGNER):
        raise InvalidStateTransitionError(f"PSBT must be updated before signing (current: {current_state})")

    _add_ecdh_shares(psbt, input_private_keys)

    sp_outputs = [om for om in psbt.o if PSBT_OUT_SP_V0_INFO in om]
    if any(PSBT_OUT_SCRIPT not in om for om in sp_outputs) and _has_full_ecdh_coverage(psbt):
        _compute_sp_output_scripts(psbt)

    if any(PSBT_OUT_SCRIPT not in om for om in sp_outputs):
        # Not every eligible input carries a share yet, so the output scripts are not
        # computable and must not be committed to by a signature.
        return psbt

    if input_indices is None:
        input_indices = [idx for idx, _ in input_private_keys]

    # Build CTransaction from PSBT for sighash computation
    tx = _build_transaction_from_psbt(psbt)

    # Build spent_utxos list for taproot sighash
    spent_utxos = []
    for input_map in psbt.i:
        witness_utxo = input_map.get(PSBT_IN_WITNESS_UTXO)
        if witness_utxo:
            # Use bitcoin_test classes to deserialize witness UTXO
            utxo = from_binary(CTxOut, witness_utxo)
        else:
            # Fallback for non-witness UTXO
            utxo = CTxOut(0, b"")
        spent_utxos.append(utxo)

    for idx, privkey_bytes in input_private_keys:
        if idx not in input_indices:
            continue
        if idx >= len(psbt.i):
            continue

        input_map = psbt.i[idx]

        # Get witness UTXO to determine script type
        witness_utxo = input_map.get(PSBT_IN_WITNESS_UTXO)
        if not witness_utxo:
            print(f"Input {idx} has no witness UTXO, skipping")
            continue

        # Parse witness UTXO using bitcoin_test classes
        utxo = from_binary(CTxOut, witness_utxo)
        amount = utxo.nValue
        scriptpubkey = utxo.scriptPubKey

        # Determine script type from scriptPubKey
        # P2WPKH: OP_0 <20 bytes>
        # P2TR: OP_1 <32 bytes>
        if is_p2wpkh(scriptpubkey):
            # P2WPKH - sign with ECDSA
            pubkey_hash = scriptpubkey[2:]
            script_code = make_p2wpkh_script_code(pubkey_hash)
            sighash = SegwitV0SignatureHash(script_code, tx, idx, SIGHASH_ALL, amount)

            key = ECKey()
            key.set(privkey_bytes, True)
            sig = key.sign_ecdsa(sighash, rfc6979=True) + bytes([SIGHASH_ALL])
            pubkey = key.get_pubkey().get_bytes()
            input_map.set_by_key(PSBT_IN_PARTIAL_SIG, pubkey, sig)

        elif is_p2tr(scriptpubkey):
            # P2TR - sign with Schnorr (key path spend)
            sighash = TaprootSignatureHash(tx, spent_utxos, SIGHASH_DEFAULT, idx)
            sig = schnorr_sign(sighash, privkey_bytes, bytes(32))
            # SIGHASH_DEFAULT (0x00) has no suffix appended
            input_map[PSBT_IN_TAP_KEY_SIG] = sig

    return psbt


# =============================================================================
# Role 5: Input Finalizer
# =============================================================================

def finalize_sp_inputs(psbt: PSBT) -> PSBT:
    """
    Input Finalizer role: Construct final scriptwitness from signatures
    and prune intermediate fields per BIP-174 (signatures, derivations).
    BIP-375 per-input SP shares (PSBT_IN_SP_ECDH_SHARE / PSBT_IN_SP_DLEQ) are
    retained so the Extractor can re-verify the output scripts and DLEQ proofs.

    Args:
        psbt: PSBT with signatures from Signer

    Returns:
        PSBT with PSBT_IN_FINAL_SCRIPTWITNESS set and intermediate fields pruned
    """
    current_state = detect_psbt_step(psbt)
    if current_state not in (PSBTState.SIGNER, PSBTState.FINALIZER):
        raise InvalidStateTransitionError(f"PSBT must have signatures to finalize inputs (current: {current_state})")

    keep_types = {
        PSBT_IN_NON_WITNESS_UTXO,
        PSBT_IN_WITNESS_UTXO,
        PSBT_IN_PREVIOUS_TXID,
        PSBT_IN_OUTPUT_INDEX,
        PSBT_IN_SEQUENCE,
        PSBT_IN_FINAL_SCRIPTWITNESS,
        # Retained for the Extractor's BIP-375 re-verification.
        PSBT_IN_SP_ECDH_SHARE,
        PSBT_IN_SP_DLEQ,
    }

    for input_map in psbt.i:
        # Check for P2WPKH partial signature
        partial_sigs = input_map.get_all_by_type(PSBT_IN_PARTIAL_SIG)
        if partial_sigs:
            pubkey, sig = partial_sigs[0]
            # P2WPKH witness: <sig> <pubkey>
            witness = bytes([2])  # witness stack count
            witness += bytes([len(sig)]) + sig
            witness += bytes([len(pubkey)]) + pubkey
            input_map[PSBT_IN_FINAL_SCRIPTWITNESS] = witness
        else:
            # Check for P2TR key path signature
            tap_key_sig = input_map.get(PSBT_IN_TAP_KEY_SIG)
            if tap_key_sig:
                # P2TR witness: <sig>
                witness = bytes([1])  # witness stack count
                witness += bytes([len(tap_key_sig)]) + tap_key_sig
                input_map[PSBT_IN_FINAL_SCRIPTWITNESS] = witness

        for k in list(input_map.map.keys()):
            kt = k if isinstance(k, int) else k[0]
            if kt not in keep_types:
                del input_map.map[k]

    return psbt


# =============================================================================
# Role 6: Extractor
# =============================================================================

def extract_sp_transaction(psbt: PSBT) -> CTransaction:
    """
    Extractor role: Build final transaction from PSBT.

    Args:
        psbt: PSBT with finalized inputs

    Returns:
        Final CTransaction object
    """
    if detect_psbt_step(psbt) != PSBTState.FINALIZER:
        raise InvalidStateTransitionError("All inputs must have final scriptwitness before extraction")

    # BIP-375: recompute the silent payment output scripts and verify they are
    # correct using the ECDH shares and DLEQ proofs, otherwise fail.
    for check in (validate_ecdh_coverage, validate_output_scripts):
        ok, msg = check(psbt)
        if not ok:
            raise ValueError(f"Extractor verification failed: {msg}")

    tx = _build_transaction_from_psbt(psbt)

    # Initialize witness structure
    tx.wit.vtxinwit = [CTxInWitness() for _ in range(len(tx.vin))]

    # Add witness data from finalized inputs
    for i, input_map in enumerate(psbt.i):
        witness_bytes = input_map[PSBT_IN_FINAL_SCRIPTWITNESS]
        tx.wit.vtxinwit[i].scriptWitness.stack = deser_string_vector(BytesIO(witness_bytes))

    return tx

# =============================================================================
# Helpers
# =============================================================================


def _deserialize_psbt_uint32(data: bytes) -> int:
    """Helper to deserialize PSBT uint32 fields"""
    return int.from_bytes(data, "little")


def _deserialize_psbt_uint64(data: bytes) -> int:
    """Helper to deserialize PSBT uint64 fields"""
    return int.from_bytes(data, "little")


def _serialize_psbt_uint32(value: int) -> bytes:
    """Helper to serialize PSBT uint32 fields"""
    return value.to_bytes(4, "little")


def _serialize_psbt_uint64(value: int) -> bytes:
    """Helper to serialize PSBT uint64 fields"""
    return value.to_bytes(8, "little")


def _build_transaction_from_psbt(psbt: PSBT) -> "CTransaction":
    """
    Build a CTransaction from PSBT fields for sighash computation.

    This is an internal helper for sign_psbt().
    """

    tx = CTransaction()

    # Version
    tx.version = _deserialize_psbt_uint32(psbt.g[PSBT_GLOBAL_TX_VERSION])

    # Inputs
    for input_map in psbt.i:
        txid_bytes = input_map[PSBT_IN_PREVIOUS_TXID]
        # COutPoint expects hash as uint256 (int), not bytes
        txid_int = int.from_bytes(txid_bytes, "little")
        vout = _deserialize_psbt_uint32(input_map[PSBT_IN_OUTPUT_INDEX])
        sequence = _deserialize_psbt_uint32(
            input_map.get(PSBT_IN_SEQUENCE, _serialize_psbt_uint32(0xFFFFFFFD))
        )

        outpoint = COutPoint(txid_int, vout)
        txin = CTxIn(outpoint, b"", sequence)
        tx.vin.append(txin)

    # Outputs
    for output_map in psbt.o:
        amount = _deserialize_psbt_uint64(output_map[PSBT_OUT_AMOUNT])
        script = output_map[PSBT_OUT_SCRIPT]
        txout = CTxOut(amount, script)
        tx.vout.append(txout)

    # nLockTime default
    tx.nLockTime = 0

    return tx


def transaction_id(psbt: PSBT) -> str:
    """Compute the BIP-375 PSBT unique identifier.

    Per BIP-370 "Unique Identification" the id is the txid of an unsigned
    transaction rebuilt from the PSBT with every input sequence forced to 0.
    BIP-375 extends this: a silent payment output's scriptPubKey is not known
    until the SP Output Finalizer runs, so the PSBT_OUT_SP_V0_INFO bytes are
    used in place of the output script. This keeps the id stable from the
    Constructor step through the Extractor.
    """
    tx = CTransaction()
    tx.version = _deserialize_psbt_uint32(psbt.g[PSBT_GLOBAL_TX_VERSION])
    tx.nLockTime = 0

    for input_map in psbt.i:
        txid_int = int.from_bytes(input_map[PSBT_IN_PREVIOUS_TXID], "little")
        vout = _deserialize_psbt_uint32(input_map[PSBT_IN_OUTPUT_INDEX])
        # sequence forced to 0 per BIP-370
        tx.vin.append(CTxIn(COutPoint(txid_int, vout), b"", 0))

    for output_map in psbt.o:
        amount = _deserialize_psbt_uint64(output_map[PSBT_OUT_AMOUNT])
        if PSBT_OUT_SP_V0_INFO in output_map:
            # Prepend the zero version byte per BIP-375.
            script = b"\x00" + output_map[PSBT_OUT_SP_V0_INFO]
        elif PSBT_OUT_SCRIPT in output_map:
            script = output_map[PSBT_OUT_SCRIPT]
        else:
            script = b""
        tx.vout.append(CTxOut(amount, script))

    return tx.txid_hex