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
from typing import Dict, List, Optional, Tuple

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
    ser_compact_size,
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
from validator.inputs import pubkey_from_eligible_input
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
from validator.bip352_crypto import compute_silent_payment_output_script

class PSBTState(Enum):
    CREATED = "created"
    CONSTRUCTED = "constructed"
    UPDATED = "updated"
    SP_FINALIZED = "sp_finalized"
    SIGNED = "signed"
    FINALIZED = "finalized"
    TRANSACTION = "transaction"

class InvalidStateTransitionError(Exception):
    """Raised when a PSBT role function is called on a PSBT in an invalid state."""
    pass

def detect_psbt_step(psbt: PSBT) -> PSBTState:
    """Detect the current workflow step of a PSBT based on its contents."""
    if len(psbt.i) < 1 and len(psbt.o) < 1:
        return PSBTState.CREATED
        
    if all(PSBT_IN_FINAL_SCRIPTWITNESS in inp for inp in psbt.i) and psbt.i:
        return PSBTState.FINALIZED
        
    has_sigs = any(inp.get_all_by_type(PSBT_IN_PARTIAL_SIG) or PSBT_IN_TAP_KEY_SIG in inp for inp in psbt.i)
    if has_sigs:
        return PSBTState.SIGNED
        
    modifiable = psbt.g.get(PSBT_GLOBAL_TX_MODIFIABLE)
    if modifiable == b'\x00':
        return PSBTState.SP_FINALIZED
        
    has_ecdh = psbt.g.get_all_by_type(PSBT_GLOBAL_SP_ECDH_SHARE) or any(inp.get_all_by_type(PSBT_IN_SP_ECDH_SHARE) for inp in psbt.i)
    if has_ecdh:
        return PSBTState.UPDATED
        
    return PSBTState.CONSTRUCTED


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
    if detect_psbt_step(psbt) != PSBTState.CREATED:
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
    input_private_keys: List[Optional[int]] = None,
) -> PSBT:
    """
    Updater role: Add UTXO info, BIP32 derivations, and ECDH shares.

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
        input_private_keys: List of private keys (int) per input for ECDH,
            aligned positionally with psbt.i; use None for inputs whose key
            this caller does not hold. Holding the key for every input produces
            a global ECDH share; holding only some produces per-input shares.

    Returns:
        PSBT with UTXO info, derivations, and optionally ECDH shares
    """
    # Allow re-entry from UPDATED so multiple parties can each add their
    # per-input shares across successive update calls (multi-party).
    if detect_psbt_step(psbt) not in (PSBTState.CONSTRUCTED, PSBTState.UPDATED):
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

    # Compute ECDH shares if private keys provided
    if input_private_keys:
        # Collect all scan keys from SP outputs
        scan_keys = set()
        for output_map in psbt.o:
            if PSBT_OUT_SP_V0_INFO in output_map:
                sp_info = output_map[PSBT_OUT_SP_V0_INFO]
                scan_keys.add(sp_info[:33])

        # BIP-375: create a global share only when this caller holds the private
        # keys for every input. Holding only some keys yields per-input shares,
        # which combine across successive updates (the multi-party case).
        held = [pk for pk in input_private_keys if pk is not None]
        if len(held) == len(psbt.i):
            # Sum all private keys for global ECDH
            a_sum = sum(held) % GE.ORDER

            for scan_key in scan_keys:
                ecdh_share, proof = _create_ecdh_share_and_proof(a_sum, scan_key)
                psbt.g.set_by_key(PSBT_GLOBAL_SP_ECDH_SHARE, scan_key, ecdh_share)
                psbt.g.set_by_key(PSBT_GLOBAL_SP_DLEQ, scan_key, proof)
        else:
            # Per-input ECDH shares for the inputs whose key is held
            for input_map, privkey in zip(psbt.i, input_private_keys):
                if privkey is None:
                    continue
                for scan_key in scan_keys:
                    ecdh_share, proof = _create_ecdh_share_and_proof(privkey, scan_key)
                    input_map.set_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key, ecdh_share)
                    input_map.set_by_key(PSBT_IN_SP_DLEQ, scan_key, proof)

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
# Role 4: SP Output Finalizer
# =============================================================================


def finalize_sp_outputs(psbt: PSBT, input_pubkeys: List[bytes] = None) -> PSBT:
    """
    SP Output Finalizer role: Compute and set output scripts for SP outputs.

    Args:
        psbt: PSBT with ECDH shares from Updater
        input_pubkeys: List of 33-byte compressed pubkeys per input
                      (if not provided, extracted from PSBT)

    Returns:
        PSBT with PSBT_OUT_SCRIPT set for SP outputs
    """
    if detect_psbt_step(psbt) != PSBTState.UPDATED:
        raise InvalidStateTransitionError("PSBT must be in 'updated' state (has ECDH shares) to finalize SP outputs")

    # Extract input pubkeys if not provided
    if input_pubkeys is None:
        input_pubkeys = []
        for input_map in psbt.i:
            pubkey = pubkey_from_eligible_input(input_map)
            if pubkey is None:
                raise ValueError(
                    "Cannot extract pubkey: no BIP32 derivation, TAP_INTERNAL_KEY, "
                    "or recognizable witness_utxo found"
                )
            input_pubkeys.append(pubkey)

    # Build outpoints list
    outpoints = []
    for input_map in psbt.i:
        txid_bytes = input_map[PSBT_IN_PREVIOUS_TXID]
        vout = _deserialize_psbt_uint32(input_map[PSBT_IN_OUTPUT_INDEX])
        txid_int = int.from_bytes(txid_bytes, "little")
        outpoints.append(COutPoint(txid_int, vout))

    # Sum input pubkeys
    summed_pubkey = None
    for pubkey in input_pubkeys:
        summed_pubkey = pubkey if summed_pubkey is None else summed_pubkey + pubkey
    summed_pubkey_bytes = summed_pubkey.to_bytes_compressed()

    # Track k values per scan key
    scan_key_k_values = {}

    # Compute output scripts for each SP output
    for output_map in psbt.o:
        if PSBT_OUT_SP_V0_INFO not in output_map:
            continue

        sp_info = output_map[PSBT_OUT_SP_V0_INFO]
        scan_key = sp_info[:33]
        spend_key = sp_info[33:]

        # Get k value for this scan key
        k = scan_key_k_values.get(scan_key, 0)

        # Get ECDH share (global or summed from per-input)
        ecdh_share = psbt.g.get_by_key(PSBT_GLOBAL_SP_ECDH_SHARE, scan_key)

        if not ecdh_share:
            # Sum per-input ECDH shares
            summed_ecdh = None
            for input_map in psbt.i:
                input_ecdh = input_map.get_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key)
                if input_ecdh:
                    point = GE.from_bytes(input_ecdh)
                    summed_ecdh = point if summed_ecdh is None else summed_ecdh + point

            if summed_ecdh is None:
                raise ValueError(f"No ECDH share found for scan key {scan_key.hex()}")
            ecdh_share = summed_ecdh.to_bytes_compressed()

        # Compute output script
        script = compute_silent_payment_output_script(
            outpoints=outpoints,
            summed_pubkey_bytes=summed_pubkey_bytes,
            ecdh_share_bytes=ecdh_share,
            spend_pubkey_bytes=spend_key,
            k=k,
        )

        output_map[PSBT_OUT_SCRIPT] = script
        scan_key_k_values[scan_key] = k + 1

    # Clear modifiable flag (no more modifications allowed)
    psbt.g[PSBT_GLOBAL_TX_MODIFIABLE] = bytes([0x00])

    return psbt


# =============================================================================
# Role 5: Signer
# =============================================================================

def sign_sp_psbt(
    psbt: PSBT,
    input_private_keys: List[Tuple[int, bytes]],
    input_indices: List[int] = None,
) -> PSBT:
    """
    Signer role: Sign inputs.

    Args:
        psbt: PSBT with finalized SP outputs
        input_private_keys: List of (index, private_key_bytes) tuples
        input_indices: Indices of inputs to sign (if None, sign all with matching keys)

    Returns:
        PSBT with signatures added

    Note: Multi-party signing is supported by calling this function multiple
    times with different private keys - the PSBT can be passed between parties.
    """
    current_state = detect_psbt_step(psbt)
    if current_state not in (PSBTState.SP_FINALIZED, PSBTState.SIGNED):
        raise InvalidStateTransitionError(f"PSBT outputs must be SP finalized before signing (current: {current_state})")

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
# Role 6: Input Finalizer
# =============================================================================

def finalize_sp_inputs(psbt: PSBT) -> PSBT:
    """
    Input Finalizer role: Construct final scriptwitness from signatures
    and prune intermediate fields per BIP-174 (signatures, derivations).
    BIP-375 per-input SP shares (PSBT_IN_SP_ECDH_SHARE / PSBT_IN_SP_DLEQ) are
    intermediate and pruned once the witness is built.

    Args:
        psbt: PSBT with signatures from Signer

    Returns:
        PSBT with PSBT_IN_FINAL_SCRIPTWITNESS set and intermediate fields pruned
    """
    current_state = detect_psbt_step(psbt)
    if current_state not in (PSBTState.SIGNED, PSBTState.FINALIZED):
        raise InvalidStateTransitionError(f"PSBT must have signatures to finalize inputs (current: {current_state})")

    keep_types = {
        PSBT_IN_NON_WITNESS_UTXO,
        PSBT_IN_WITNESS_UTXO,
        PSBT_IN_PREVIOUS_TXID,
        PSBT_IN_OUTPUT_INDEX,
        PSBT_IN_SEQUENCE,
        PSBT_IN_FINAL_SCRIPTWITNESS,
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
# Role 7: Extractor
# =============================================================================

# TODO: Validate final transaction correctness
def extract_sp_transaction(psbt: PSBT) -> CTransaction:
    """
    Extractor role: Build final transaction from PSBT.

    Args:
        psbt: PSBT with finalized inputs

    Returns:
        Final CTransaction object
    """
    if detect_psbt_step(psbt) != PSBTState.FINALIZED:
        raise InvalidStateTransitionError("All inputs must have final scriptwitness before extraction")

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