#!/usr/bin/env python3
# Copyright (c) 2010-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Sighash computation for BIP143 (SegWit v0) and BIP341 (Taproot).

Adapted from Bitcoin Core test framework script.py.
"""

from .utils import hash256, sha256, ser_string
from .transaction import CTransaction


# Sighash types
SIGHASH_DEFAULT = 0  # Taproot-only default, semantics same as SIGHASH_ALL
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

# Tapscript leaf version
LEAF_VERSION_TAPSCRIPT = 0xC0


def tagged_hash(tag: str, data: bytes) -> bytes:
    """Compute BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    import hashlib

    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


# =============================================================================
# BIP143 - SegWit v0 Sighash (for P2WPKH)
# =============================================================================


def SegwitV0SignatureMsg(
    script: bytes, txTo: CTransaction, inIdx: int, hashtype: int, amount: int
) -> bytes:
    """
    Compute the BIP143 sighash preimage for SegWit v0 inputs.

    Args:
        script: The scriptCode (for P2WPKH: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG)
        txTo: The transaction being signed
        inIdx: Index of the input being signed
        hashtype: Sighash type (SIGHASH_ALL, etc.)
        amount: Value of the input being spent (in satoshis)

    Returns:
        The preimage bytes to be hashed
    """
    ZERO_HASH = bytes(32)

    hashPrevouts = ZERO_HASH
    hashSequence = ZERO_HASH
    hashOutputs = ZERO_HASH

    # hashPrevouts
    if not (hashtype & SIGHASH_ANYONECANPAY):
        serialize_prevouts = b"".join(i.prevout.serialize() for i in txTo.vin)
        hashPrevouts = hash256(serialize_prevouts)

    # hashSequence
    if (
        not (hashtype & SIGHASH_ANYONECANPAY)
        and (hashtype & 0x1F) != SIGHASH_SINGLE
        and (hashtype & 0x1F) != SIGHASH_NONE
    ):
        serialize_sequence = b"".join(
            i.nSequence.to_bytes(4, "little") for i in txTo.vin
        )
        hashSequence = hash256(serialize_sequence)

    # hashOutputs
    if (hashtype & 0x1F) != SIGHASH_SINGLE and (hashtype & 0x1F) != SIGHASH_NONE:
        serialize_outputs = b"".join(o.serialize() for o in txTo.vout)
        hashOutputs = hash256(serialize_outputs)
    elif (hashtype & 0x1F) == SIGHASH_SINGLE and inIdx < len(txTo.vout):
        serialize_outputs = txTo.vout[inIdx].serialize()
        hashOutputs = hash256(serialize_outputs)

    # Construct preimage
    ss = txTo.version.to_bytes(4, "little")
    ss += hashPrevouts
    ss += hashSequence
    ss += txTo.vin[inIdx].prevout.serialize()
    ss += ser_string(script)
    ss += amount.to_bytes(8, "little", signed=True)
    ss += txTo.vin[inIdx].nSequence.to_bytes(4, "little")
    ss += hashOutputs
    ss += txTo.nLockTime.to_bytes(4, "little")
    ss += hashtype.to_bytes(4, "little")

    return ss


def SegwitV0SignatureHash(
    script: bytes, txTo: CTransaction, inIdx: int, hashtype: int, amount: int
) -> bytes:
    """
    Compute the BIP143 sighash for SegWit v0 inputs.

    Returns:
        32-byte sighash
    """
    return hash256(SegwitV0SignatureMsg(script, txTo, inIdx, hashtype, amount))


def make_p2wpkh_script_code(pubkey_hash: bytes) -> bytes:
    """
    Create the scriptCode for P2WPKH signing.

    For P2WPKH, the scriptCode is: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG

    Args:
        pubkey_hash: 20-byte hash160 of the public key

    Returns:
        25-byte scriptCode
    """
    assert len(pubkey_hash) == 20
    return bytes([0x76, 0xA9, 0x14]) + pubkey_hash + bytes([0x88, 0xAC])


# =============================================================================
# BIP341 - Taproot Sighash (for P2TR)
# =============================================================================


def BIP341_sha_prevouts(txTo: CTransaction) -> bytes:
    """SHA256 of all input prevouts."""
    return sha256(b"".join(i.prevout.serialize() for i in txTo.vin))


def BIP341_sha_amounts(spent_utxos: list) -> bytes:
    """SHA256 of all input amounts."""
    return sha256(
        b"".join(u.nValue.to_bytes(8, "little", signed=True) for u in spent_utxos)
    )


def BIP341_sha_scriptpubkeys(spent_utxos: list) -> bytes:
    """SHA256 of all input scriptPubKeys."""
    return sha256(b"".join(ser_string(u.scriptPubKey) for u in spent_utxos))


def BIP341_sha_sequences(txTo: CTransaction) -> bytes:
    """SHA256 of all input sequences."""
    return sha256(b"".join(i.nSequence.to_bytes(4, "little") for i in txTo.vin))


def BIP341_sha_outputs(txTo: CTransaction) -> bytes:
    """SHA256 of all outputs."""
    return sha256(b"".join(o.serialize() for o in txTo.vout))


def TaprootSignatureMsg(
    txTo: CTransaction,
    spent_utxos: list,
    hash_type: int,
    input_index: int = 0,
    *,
    scriptpath: bool = False,
    leaf_script: bytes = None,
    codeseparator_pos: int = -1,
    annex: bytes = None,
    leaf_ver: int = LEAF_VERSION_TAPSCRIPT,
) -> bytes:
    """
    Compute the BIP341 sighash preimage for Taproot inputs.

    Args:
        txTo: The transaction being signed
        spent_utxos: List of CTxOut for all inputs (amounts and scriptPubKeys)
        hash_type: Sighash type (SIGHASH_DEFAULT, SIGHASH_ALL, etc.)
        input_index: Index of the input being signed
        scriptpath: Whether this is a script path spend (default: key path)
        leaf_script: The leaf script (required if scriptpath=True)
        codeseparator_pos: Position of last OP_CODESEPARATOR (-1 if none)
        annex: Annex data (if any)
        leaf_ver: Leaf version (default: 0xC0 for tapscript)

    Returns:
        The preimage bytes to be hashed with TapSighash tag
    """
    assert len(txTo.vin) == len(spent_utxos)
    assert input_index < len(txTo.vin)

    out_type = SIGHASH_ALL if hash_type == 0 else hash_type & 3
    in_type = hash_type & SIGHASH_ANYONECANPAY

    # Epoch and hash_type
    ss = bytes([0, hash_type])
    ss += txTo.version.to_bytes(4, "little")
    ss += txTo.nLockTime.to_bytes(4, "little")

    if in_type != SIGHASH_ANYONECANPAY:
        ss += BIP341_sha_prevouts(txTo)
        ss += BIP341_sha_amounts(spent_utxos)
        ss += BIP341_sha_scriptpubkeys(spent_utxos)
        ss += BIP341_sha_sequences(txTo)

    if out_type == SIGHASH_ALL:
        ss += BIP341_sha_outputs(txTo)

    # Spend type
    spend_type = 0
    if annex is not None:
        spend_type |= 1
    if scriptpath:
        spend_type |= 2
    ss += bytes([spend_type])

    if in_type == SIGHASH_ANYONECANPAY:
        ss += txTo.vin[input_index].prevout.serialize()
        ss += spent_utxos[input_index].nValue.to_bytes(8, "little", signed=True)
        ss += ser_string(spent_utxos[input_index].scriptPubKey)
        ss += txTo.vin[input_index].nSequence.to_bytes(4, "little")
    else:
        ss += input_index.to_bytes(4, "little")

    if spend_type & 1:  # annex present
        ss += sha256(ser_string(annex))

    if out_type == SIGHASH_SINGLE:
        if input_index < len(txTo.vout):
            ss += sha256(txTo.vout[input_index].serialize())
        else:
            ss += bytes(32)

    if scriptpath:
        ss += tagged_hash("TapLeaf", bytes([leaf_ver]) + ser_string(leaf_script))
        ss += bytes([0])  # key_version
        ss += codeseparator_pos.to_bytes(4, "little", signed=False)

    return ss


def TaprootSignatureHash(
    txTo: CTransaction,
    spent_utxos: list,
    hash_type: int,
    input_index: int = 0,
    **kwargs,
) -> bytes:
    """
    Compute the BIP341 sighash for Taproot inputs.

    Returns:
        32-byte sighash
    """
    return tagged_hash(
        "TapSighash",
        TaprootSignatureMsg(txTo, spent_utxos, hash_type, input_index, **kwargs),
    )
