#!/usr/bin/env python3
"""
BIP-375 reference PSBT v2 roles for silent payments

Creator, Constructor, Updater, Signer, Input Finalizer and Extractor as BIP-370
defines them, with the BIP-375 rules for silent payment outputs. Each role
checks its own preconditions from the PSBT's contents.

The Signer signs P2PKH, P2WPKH and P2TR key-path inputs and raises
NotImplementedError for any other input it holds a key for. A Signer holding
every eligible input's key contributes one global ECDH share; one holding only
some contributes per-input shares, which combine across Signers until every
eligible input is covered.

The Input Finalizer also assembles P2SH multisig scriptSigs and NUMS
script-path witnesses from signatures other Signers have added, and the
Extractor copies a final scriptSig into the transaction.
"""

import secrets
import struct
from io import BytesIO

from deps.bitcoin_test.key import ECKey
from deps.bitcoin_test.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    deser_string_vector,
    from_binary,
    ser_compact_size,
    ser_string_vector,
)
from deps.bitcoin_test.psbt import (
    PSBT_GLOBAL_FALLBACK_LOCKTIME,
    PSBT_GLOBAL_INPUT_COUNT,
    PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_TX_MODIFIABLE,
    PSBT_GLOBAL_TX_VERSION,
    PSBT_GLOBAL_VERSION,
    PSBT_IN_BIP32_DERIVATION,
    PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME,
    PSBT_IN_REQUIRED_TIME_LOCKTIME,
    PSBT_IN_SEQUENCE,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_TAP_LEAF_SCRIPT,
    PSBT_IN_TAP_SCRIPT_SIG,
    PSBT_IN_WITNESS_UTXO,
    PSBT_OUT_AMOUNT,
    PSBT_OUT_SCRIPT,
)
from deps.bitcoin_test.script import (
    CScript,
    LegacySignatureHash,
    OP_0,
    SegwitV0SignatureHash,
    SIGHASH_ALL,
    SIGHASH_DEFAULT,
    TaprootSignatureHash,
)
from deps.bitcoin_test.script_util import keyhash_to_p2pkh_script
from deps.dleq import dleq_generate_proof
from secp256k1lab.bip340 import schnorr_sign
from secp256k1lab.secp256k1 import G, GE
from validator.inputs import (
    is_input_eligible,
    is_p2pkh,
    is_p2tr,
    is_p2wpkh,
    scan_key_is_covered,
    script_pubkey_from_psbt_input,
    sp_scan_keys,
)
from validator.psbt_bip375 import (
    BIP375PSBT,
    BIP375PSBTMap,
    PSBT_GLOBAL_SP_DLEQ,
    PSBT_GLOBAL_SP_ECDH_SHARE,
    PSBT_IN_SP_DLEQ,
    PSBT_IN_SP_ECDH_SHARE,
    PSBT_OUT_SP_V0_INFO,
)
from validator.validate_psbt import derive_sp_output_scripts, run_checks

# PSBT_GLOBAL_TX_MODIFIABLE flags (BIP-370)
INPUTS_MODIFIABLE = 0x01
OUTPUTS_MODIFIABLE = 0x02


# =============================================================================
# Creator
# =============================================================================


def create_psbt(tx_version: int = 2) -> BIP375PSBT:
    """Creator role: an empty PSBT v2 whose inputs and outputs are modifiable"""
    psbt = BIP375PSBT()
    psbt.g[PSBT_GLOBAL_VERSION] = struct.pack("<I", 2)
    psbt.g[PSBT_GLOBAL_TX_VERSION] = struct.pack("<I", tx_version)
    psbt.g[PSBT_GLOBAL_TX_MODIFIABLE] = bytes([INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE])
    psbt.g[PSBT_GLOBAL_INPUT_COUNT] = ser_compact_size(0)
    psbt.g[PSBT_GLOBAL_OUTPUT_COUNT] = ser_compact_size(0)
    return psbt


# =============================================================================
# Constructor
# =============================================================================


def construct_sp_psbt(
    psbt: BIP375PSBT,
    inputs: list[dict],
    sp_outputs: list[dict],
    regular_outputs: list[dict],
) -> BIP375PSBT:
    """
    Constructor role: add inputs and outputs, as the modifiable flags allow.

    Args:
        psbt: PSBT from the Creator
        inputs: input dicts with keys:
            - txid: bytes (32 bytes, internal byte order)
            - vout: int
            - sequence: int (optional; omitted means final, 0xFFFFFFFF, per BIP-370)
        sp_outputs: silent payment output dicts with keys:
            - scan_key: bytes (33-byte compressed pubkey)
            - spend_key: bytes (33-byte compressed pubkey)
            - amount: int (satoshis)
        regular_outputs: regular output dicts with keys:
            - script: bytes (scriptPubKey)
            - amount: int (satoshis)
    """
    flags = _tx_modifiable_flags(psbt)
    if inputs and not flags & INPUTS_MODIFIABLE:
        raise ValueError("Constructor cannot add inputs: Inputs Modifiable is not set")
    if (sp_outputs or regular_outputs) and not flags & OUTPUTS_MODIFIABLE:
        raise ValueError("Constructor cannot add outputs: Outputs Modifiable is not set")

    for inp in inputs:
        input_map = BIP375PSBTMap()
        input_map[PSBT_IN_PREVIOUS_TXID] = inp["txid"]
        input_map[PSBT_IN_OUTPUT_INDEX] = struct.pack("<I", inp["vout"])
        if "sequence" in inp:
            input_map[PSBT_IN_SEQUENCE] = struct.pack("<I", inp["sequence"])
        psbt.i.append(input_map)

    for sp_out in sp_outputs:
        output_map = BIP375PSBTMap()
        output_map[PSBT_OUT_SP_V0_INFO] = sp_out["scan_key"] + sp_out["spend_key"]
        output_map[PSBT_OUT_AMOUNT] = struct.pack("<q", sp_out["amount"])
        psbt.o.append(output_map)

    for reg_out in regular_outputs:
        output_map = BIP375PSBTMap()
        output_map[PSBT_OUT_SCRIPT] = reg_out["script"]
        output_map[PSBT_OUT_AMOUNT] = struct.pack("<q", reg_out["amount"])
        psbt.o.append(output_map)

    psbt.g[PSBT_GLOBAL_INPUT_COUNT] = ser_compact_size(len(psbt.i))
    psbt.g[PSBT_GLOBAL_OUTPUT_COUNT] = ser_compact_size(len(psbt.o))
    return psbt


# =============================================================================
# Updater
# =============================================================================


def update_sp_psbt(
    psbt: BIP375PSBT,
    input_utxos: list[dict],
    input_derivations: list[dict],
) -> BIP375PSBT:
    """
    Updater role: add each input's UTXO and BIP32 derivation.

    The Updater holds no private key; the ECDH shares and DLEQ proofs are
    Signer material (see sign_sp_psbt).

    Args:
        psbt: PSBT from the Constructor
        input_utxos: one dict per input, with either key:
            - witness_utxo: bytes (serialized output)
            - non_witness_utxo: bytes (serialized previous transaction)
        input_derivations: one dict per input with keys:
            - pubkey: bytes (33-byte compressed pubkey)
            - fingerprint: bytes (4 bytes, zero to withhold the origin)
            - path: list[int] (derivation path indices)
    """
    for input_map, utxo, deriv in zip(psbt.i, input_utxos, input_derivations):
        if "witness_utxo" in utxo:
            input_map[PSBT_IN_WITNESS_UTXO] = utxo["witness_utxo"]
        else:
            input_map[PSBT_IN_NON_WITNESS_UTXO] = utxo["non_witness_utxo"]

        # Value: fingerprint, then each path index as a little-endian uint32
        value = deriv["fingerprint"] + b"".join(struct.pack("<I", idx) for idx in deriv["path"])
        input_map.set_by_key(PSBT_IN_BIP32_DERIVATION, deriv["pubkey"], value)
    return psbt


# =============================================================================
# Signer
# =============================================================================


def sign_sp_psbt(
    psbt: BIP375PSBT,
    input_private_keys: list[tuple[int, bytes]],
    dleq_aux_rand: dict[tuple[bytes, int | None], bytes] | None = None,
) -> BIP375PSBT:
    """
    Signer role, following the BIP-375 Signer rules in order: verify the PSBT and
    the other Signers' DLEQ proofs, add this Signer's ECDH shares and DLEQ proofs,
    set the output scripts once every eligible input is covered, and sign only
    once every silent payment output has its script.

    A Signer that cannot yet set the output scripts (another Signer's share is
    still missing) returns the PSBT unsigned and signs on a later call, once the
    last Signer has set them.

    Args:
        psbt: PSBT from the Updater, or from a previous Signer
        input_private_keys: (input index, private key) for each input whose key
            this Signer holds
        dleq_aux_rand: optional map of (scan_key, input_index) to the 32-byte
            randomness a DLEQ proof must use, to reproduce a specific proof (a test
            vector's disclosed randomness). input_index is None for a global share.
            Without an entry, fresh randomness is drawn.
    """
    _verify_for_signer(psbt)
    _add_ecdh_shares(psbt, input_private_keys, dleq_aux_rand or {})
    if not _sp_output_scripts_set(psbt):
        if not _has_full_ecdh_coverage(psbt):
            # BIP-375: while an output script is missing, the Signer must not yet
            # add a signature
            return psbt
        _set_sp_output_scripts(psbt)
    _sign_inputs(psbt, input_private_keys)
    return psbt


def _verify_for_signer(psbt: BIP375PSBT) -> None:
    """Fail unless the PSBT passes every BIP-375 check: other Signers' DLEQ proofs,
    any output scripts already set, no segwit v>1 input, and no provided sighash
    type other than SIGHASH_ALL (or SIGHASH_DEFAULT on taproot)."""
    ok, msg, _ = run_checks(psbt)
    if not ok:
        raise ValueError(f"Signer verification failed: {msg}")


def _add_ecdh_shares(
    psbt: BIP375PSBT,
    input_private_keys: list[tuple[int, bytes]],
    dleq_aux_rand: dict[tuple[bytes, int | None], bytes],
) -> None:
    """Add this Signer's ECDH shares and DLEQ proofs.

    A Signer holding the private key for every eligible input sets a single global
    share over the summed keys; one holding only some sets per-input shares. Shares
    already in the PSBT are left alone, so another Signer's DLEQ proof is never
    overwritten.
    """
    scan_keys = sp_scan_keys(psbt)
    # BIP-352 sums only eligible inputs' keys, so a held key for an ineligible
    # input contributes no share
    eligible = {idx for idx, inp in enumerate(psbt.i) if is_input_eligible(inp)}
    held = [(idx, key) for idx, key in input_private_keys if idx in eligible]
    if not scan_keys or not held:
        return

    privkeys = {
        idx: _normalized_input_privkey(psbt.i[idx], int.from_bytes(key, "big"))
        for idx, key in held
    }

    if privkeys.keys() == eligible:
        a_sum = sum(privkeys.values()) % GE.ORDER
        for scan_key in scan_keys:
            # A global share adds nothing to a scan key that is already covered
            if scan_key_is_covered(psbt, scan_key):
                continue
            ecdh_share, proof = _create_ecdh_share_and_proof(
                a_sum, scan_key, dleq_aux_rand.get((scan_key, None))
            )
            psbt.g.set_by_key(PSBT_GLOBAL_SP_ECDH_SHARE, scan_key, ecdh_share)
            psbt.g.set_by_key(PSBT_GLOBAL_SP_DLEQ, scan_key, proof)
        return

    for idx, a in privkeys.items():
        input_map = psbt.i[idx]
        for scan_key in scan_keys:
            if input_map.get_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key):
                continue
            ecdh_share, proof = _create_ecdh_share_and_proof(
                a, scan_key, dleq_aux_rand.get((scan_key, idx))
            )
            input_map.set_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key, ecdh_share)
            input_map.set_by_key(PSBT_IN_SP_DLEQ, scan_key, proof)


def _normalized_input_privkey(input_map: BIP375PSBTMap, d0: int) -> int:
    """BIP-352: a taproot input contributes the private key of its x-only output
    key, which is always the even-Y point, so d0 is negated if d0 * G has odd Y.
    A non-taproot input's compressed pubkey already fixes the parity."""
    if is_p2tr(script_pubkey_from_psbt_input(input_map)) and not (d0 * G).has_even_y():
        return GE.ORDER - d0
    return d0


def _create_ecdh_share_and_proof(
    a: int, scan_key: bytes, aux_rand: bytes | None
) -> tuple[bytes, bytes]:
    """ECDH share a * B_scan and its BIP-374 DLEQ proof. Fresh randomness is drawn
    unless aux_rand is given."""
    B_scan = GE.from_bytes(scan_key)
    r = aux_rand if aux_rand is not None else secrets.token_bytes(32)
    proof = dleq_generate_proof(a, B_scan, r)
    if proof is None:
        raise ValueError("Failed to generate DLEQ proof")
    return (a * B_scan).to_bytes_compressed(), proof


def _sp_output_scripts_set(psbt: BIP375PSBT) -> bool:
    """True when every silent payment output has its PSBT_OUT_SCRIPT"""
    return all(PSBT_OUT_SCRIPT in om for om in psbt.o if PSBT_OUT_SP_V0_INFO in om)


def _has_full_ecdh_coverage(psbt: BIP375PSBT) -> bool:
    """True when every scan key is covered by a global share, or by a per-input
    share on every eligible input. Only then can the output scripts be set."""
    return all(scan_key_is_covered(psbt, sk) for sk in sp_scan_keys(psbt))


def _set_sp_output_scripts(psbt: BIP375PSBT) -> None:
    """Set PSBT_OUT_SCRIPT on every silent payment output, and clear the Inputs
    Modifiable and Outputs Modifiable flags as BIP-375 requires of a Signer that
    sets them. The caller has checked that every scan key is covered."""
    for output_idx, output_map, script in derive_sp_output_scripts(psbt):
        if script is None:
            raise ValueError(
                f"Cannot compute output {output_idx} script: missing ECDH share or input pubkeys"
            )
        output_map[PSBT_OUT_SCRIPT] = script

    flags = _tx_modifiable_flags(psbt) & ~(INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE)
    psbt.g[PSBT_GLOBAL_TX_MODIFIABLE] = bytes([flags])


def _sign_inputs(psbt: BIP375PSBT, input_private_keys: list[tuple[int, bytes]]) -> None:
    """Sign every input this Signer holds a key for. _verify_for_signer has
    rejected any provided sighash type other than SIGHASH_ALL (SIGHASH_DEFAULT on
    taproot), so the ECDSA inputs always sign SIGHASH_ALL."""
    tx = _unsigned_tx(psbt)
    # The taproot sighash commits to every spent output
    spent_utxos = [_spent_utxo(input_map) for input_map in psbt.i]

    for idx, privkey in input_private_keys:
        input_map = psbt.i[idx]
        script_pubkey = spent_utxos[idx].scriptPubKey

        if is_p2pkh(script_pubkey):
            sighash, err = LegacySignatureHash(CScript(script_pubkey), tx, idx, SIGHASH_ALL)
            if err is not None:
                raise ValueError(f"Input {idx}: {err}")
            _add_ecdsa_sig(input_map, privkey, sighash)
        elif is_p2wpkh(script_pubkey):
            # BIP-143: a P2WPKH scriptCode is the P2PKH script of the same key hash
            script_code = keyhash_to_p2pkh_script(script_pubkey[2:])
            sighash = SegwitV0SignatureHash(
                script_code, tx, idx, SIGHASH_ALL, spent_utxos[idx].nValue
            )
            _add_ecdsa_sig(input_map, privkey, sighash)
        elif is_p2tr(script_pubkey) and is_input_eligible(input_map):
            # Key-path spend: the disclosed key is the output key's private key, so it
            # signs directly. An omitted PSBT_IN_SIGHASH_TYPE means SIGHASH_DEFAULT,
            # which the signature signals by omitting the trailing type byte.
            sighash_field = input_map.get(PSBT_IN_SIGHASH_TYPE)
            sighash_type = struct.unpack("<I", sighash_field)[0] if sighash_field else SIGHASH_DEFAULT
            sighash = TaprootSignatureHash(tx, spent_utxos, sighash_type, idx)
            sig = schnorr_sign(sighash, privkey, bytes(32))
            if sighash_type != SIGHASH_DEFAULT:
                sig += bytes([sighash_type])
            input_map[PSBT_IN_TAP_KEY_SIG] = sig
        else:
            # TODO: P2SH-P2WPKH and taproot script-path signing are not implemented (a
            # NUMS input has no key path). Fail rather than leave a held input unsigned.
            raise NotImplementedError(
                f"Input {idx}: only P2PKH, P2WPKH and P2TR key-path signing is implemented"
            )


def _add_ecdsa_sig(input_map: BIP375PSBTMap, privkey: bytes, sighash: bytes) -> None:
    """Add a SIGHASH_ALL ECDSA PSBT_IN_PARTIAL_SIG for a compressed key"""
    key = ECKey()
    key.set(privkey, True)
    sig = key.sign_ecdsa(sighash, rfc6979=True) + bytes([SIGHASH_ALL])
    input_map.set_by_key(PSBT_IN_PARTIAL_SIG, key.get_pubkey().get_bytes(), sig)


def _spent_utxo(input_map: BIP375PSBTMap) -> CTxOut:
    """The output an input spends, from PSBT_IN_WITNESS_UTXO or, failing that, the
    previous transaction in PSBT_IN_NON_WITNESS_UTXO"""
    witness_utxo = input_map.get(PSBT_IN_WITNESS_UTXO)
    if witness_utxo:
        return from_binary(CTxOut, witness_utxo)
    if PSBT_IN_NON_WITNESS_UTXO in input_map:
        prev_tx = from_binary(CTransaction, input_map[PSBT_IN_NON_WITNESS_UTXO])
        return prev_tx.vout[struct.unpack("<I", input_map[PSBT_IN_OUTPUT_INDEX])[0]]
    raise ValueError("every input needs a UTXO to compute the sighash")


# =============================================================================
# Input Finalizer
# =============================================================================

# Fields a final input keeps: the transaction fields (the Extractor rebuilds the
# signed lock time from the required lock times), the UTXOs, the final scripts,
# and the BIP-375 shares and proofs the Extractor verifies
_FINAL_INPUT_TYPES = {
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_WITNESS_UTXO,
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_SEQUENCE,
    PSBT_IN_REQUIRED_TIME_LOCKTIME,
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME,
    PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_SP_ECDH_SHARE,
    PSBT_IN_SP_DLEQ,
}


def finalize_sp_inputs(psbt: BIP375PSBT) -> BIP375PSBT:
    """
    Input Finalizer role: build the final scriptSig or witness of every input that
    carries its signatures, and clear that input's other fields per BIP-174. An
    input without signatures is left as it is.
    """
    for input_map in psbt.i:
        if not _finalize_input(input_map):
            continue
        for key in list(input_map.map):
            key_type = key if isinstance(key, int) else key[0]
            if key_type not in _FINAL_INPUT_TYPES:
                del input_map.map[key]
    return psbt


def _finalize_input(input_map: BIP375PSBTMap) -> bool:
    """Set PSBT_IN_FINAL_SCRIPTSIG or PSBT_IN_FINAL_SCRIPTWITNESS from the input's
    signatures. Returns False if it has none to finalize."""
    script_pubkey = script_pubkey_from_psbt_input(input_map)
    partial_sigs = input_map.get_all_by_type(PSBT_IN_PARTIAL_SIG)
    redeem_script = input_map.get(PSBT_IN_REDEEM_SCRIPT)
    tap_script_sigs = input_map.get_all_by_type(PSBT_IN_TAP_SCRIPT_SIG)

    if redeem_script is not None and len(partial_sigs) > 1:
        # P2SH multisig: OP_0 <sig>... <redeemScript>. OP_0 absorbs the extra item
        # OP_CHECKMULTISIG pops, and the signatures go in redeemScript pubkey order,
        # which is the order OP_CHECKMULTISIG matches them in.
        pubkeys = [item for item in CScript(redeem_script) if isinstance(item, bytes)]
        sigs = [
            sig
            for pubkey in pubkeys
            if (sig := input_map.get_by_key(PSBT_IN_PARTIAL_SIG, pubkey)) is not None
        ]
        input_map[PSBT_IN_FINAL_SCRIPTSIG] = bytes(CScript([OP_0, *sigs, redeem_script]))
    elif partial_sigs:
        pubkey, sig = partial_sigs[0]
        if is_p2pkh(script_pubkey):
            input_map[PSBT_IN_FINAL_SCRIPTSIG] = bytes(CScript([sig, pubkey]))
        elif is_p2wpkh(script_pubkey):
            input_map[PSBT_IN_FINAL_SCRIPTWITNESS] = ser_string_vector([sig, pubkey])
        elif redeem_script is not None and is_p2wpkh(redeem_script):
            # P2SH-P2WPKH: the scriptSig pushes the redeem script
            input_map[PSBT_IN_FINAL_SCRIPTSIG] = bytes(CScript([redeem_script]))
            input_map[PSBT_IN_FINAL_SCRIPTWITNESS] = ser_string_vector([sig, pubkey])
        else:
            raise NotImplementedError("only P2PKH, P2WPKH, P2SH-P2WPKH and P2SH multisig ECDSA inputs can be finalized")
    elif PSBT_IN_TAP_KEY_SIG in input_map:
        input_map[PSBT_IN_FINAL_SCRIPTWITNESS] = ser_string_vector([input_map[PSBT_IN_TAP_KEY_SIG]])
    elif tap_script_sigs:
        # NUMS script path: <sig> <leafScript> <controlBlock>. One leaf and one
        # signature; choosing among several is out of scope.
        _, sig = tap_script_sigs[0]
        control_block, leaf_value = input_map.get_all_by_type(PSBT_IN_TAP_LEAF_SCRIPT)[0]
        leaf_script = leaf_value[:-1]  # drop the trailing leaf version byte
        input_map[PSBT_IN_FINAL_SCRIPTWITNESS] = ser_string_vector([sig, leaf_script, control_block])
    else:
        return False
    return True


# =============================================================================
# Extractor
# =============================================================================


def extract_sp_transaction(psbt: BIP375PSBT) -> CTransaction:
    """
    Extractor role: verify the silent payment output scripts from the ECDH shares
    and DLEQ proofs, as BIP-375 requires, then build the final transaction.
    """
    if not all(
        PSBT_IN_FINAL_SCRIPTSIG in inp or PSBT_IN_FINAL_SCRIPTWITNESS in inp for inp in psbt.i
    ):
        raise ValueError("every input must be finalized before extraction")

    ok, msg, _ = run_checks(psbt, ["ecdh_coverage", "output_scripts"])
    if not ok:
        raise ValueError(f"Extractor verification failed: {msg}")

    tx = _unsigned_tx(psbt)
    tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
    for txin, txinwit, input_map in zip(tx.vin, tx.wit.vtxinwit, psbt.i):
        witness = input_map.get(PSBT_IN_FINAL_SCRIPTWITNESS)
        if witness is not None:
            txinwit.scriptWitness.stack = deser_string_vector(BytesIO(witness))
        script_sig = input_map.get(PSBT_IN_FINAL_SCRIPTSIG)
        if script_sig is not None:
            txin.scriptSig = script_sig
    return tx


# =============================================================================
# Transaction and unique identifier
# =============================================================================


def transaction_id(psbt: BIP375PSBT) -> str:
    """Compute the BIP-375 PSBT unique identifier.

    Per BIP-370 "Unique Identification" the id is the txid of an unsigned
    transaction rebuilt from the PSBT with every input sequence set to 0.
    BIP-375 extends this: a silent payment output's scriptPubKey is not known
    until the Signer computes it, and the PSBT is valid with or without
    PSBT_OUT_SCRIPT, so a zero version byte followed by PSBT_OUT_SP_V0_INFO is
    always used in place of the output script. This keeps the id stable from
    the Constructor through the Extractor.
    """
    return _unsigned_tx(psbt, unique_id=True).txid_hex


def _unsigned_tx(psbt: BIP375PSBT, unique_id: bool = False) -> CTransaction:
    """The unsigned transaction a PSBT describes, per BIP-370. With unique_id,
    the variant transaction_id hashes instead."""
    tx = CTransaction()
    tx.version = struct.unpack("<I", psbt.g[PSBT_GLOBAL_TX_VERSION])[0]
    tx.nLockTime = _determine_locktime(psbt)

    for input_map in psbt.i:
        outpoint = COutPoint(
            int.from_bytes(input_map[PSBT_IN_PREVIOUS_TXID], "little"),
            struct.unpack("<I", input_map[PSBT_IN_OUTPUT_INDEX])[0],
        )
        if unique_id:
            sequence = 0
        elif PSBT_IN_SEQUENCE in input_map:
            sequence = struct.unpack("<I", input_map[PSBT_IN_SEQUENCE])[0]
        else:
            sequence = 0xFFFFFFFF  # BIP-370: an omitted sequence is final
        tx.vin.append(CTxIn(outpoint, b"", sequence))

    for output_map in psbt.o:
        amount = struct.unpack("<q", output_map[PSBT_OUT_AMOUNT])[0]
        if unique_id and PSBT_OUT_SP_V0_INFO in output_map:
            script = b"\x00" + output_map[PSBT_OUT_SP_V0_INFO]
        else:
            script = output_map[PSBT_OUT_SCRIPT]
        tx.vout.append(CTxOut(amount, script))
    return tx


def _determine_locktime(psbt: BIP375PSBT) -> int:
    """BIP-370 lock time determination.

    With no input requiring a lock time, use PSBT_GLOBAL_FALLBACK_LOCKTIME (0 if
    omitted). Otherwise take the maximum of the one lock time type every requiring
    input supports, preferring height when both are possible, and fail if none is.
    """
    required = [
        (inp.get(PSBT_IN_REQUIRED_HEIGHT_LOCKTIME), inp.get(PSBT_IN_REQUIRED_TIME_LOCKTIME))
        for inp in psbt.i
    ]
    required = [r for r in required if r != (None, None)]
    if not required:
        fallback = psbt.g.get(PSBT_GLOBAL_FALLBACK_LOCKTIME)
        return struct.unpack("<I", fallback)[0] if fallback else 0

    for pos in (0, 1):  # height, then time
        if all(r[pos] is not None for r in required):
            return max(struct.unpack("<I", r[pos])[0] for r in required)
    raise ValueError("inputs require incompatible lock time types")


def _tx_modifiable_flags(psbt: BIP375PSBT) -> int:
    """PSBT_GLOBAL_TX_MODIFIABLE as an int; an omitted field is 0"""
    flags = psbt.g.get(PSBT_GLOBAL_TX_MODIFIABLE)
    return flags[0] if flags else 0
