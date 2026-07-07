#!/usr/bin/env python3
# Copyright (c) 2010-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Bitcoin transaction data structures.

Adapted from Bitcoin Core test framework messages.py.
"""

import copy
import math

from .utils import (
    hash256,
    ser_string,
    deser_string,
    ser_uint256,
    deser_uint256,
    ser_vector,
    deser_vector,
    ser_string_vector,
    deser_string_vector,
    uint256_from_str,
)


COIN = 100000000  # 1 btc in satoshis
WITNESS_SCALE_FACTOR = 4


class COutPoint:
    """Previous output reference (txid + index)."""

    __slots__ = ("hash", "n")

    def __init__(self, hash=0, n=0):
        self.hash = hash
        self.n = n

    def deserialize(self, f):
        self.hash = deser_uint256(f)
        self.n = int.from_bytes(f.read(4), "little")

    def serialize(self):
        r = ser_uint256(self.hash)
        r += self.n.to_bytes(4, "little")
        return r

    def __repr__(self):
        return "COutPoint(hash=%064x n=%i)" % (self.hash, self.n)


class CTxIn:
    """Transaction input."""

    __slots__ = ("nSequence", "prevout", "scriptSig")

    def __init__(self, outpoint=None, scriptSig=b"", nSequence=0):
        if outpoint is None:
            self.prevout = COutPoint()
        else:
            self.prevout = outpoint
        self.scriptSig = scriptSig
        self.nSequence = nSequence

    def deserialize(self, f):
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = int.from_bytes(f.read(4), "little")

    def serialize(self):
        r = self.prevout.serialize()
        r += ser_string(self.scriptSig)
        r += self.nSequence.to_bytes(4, "little")
        return r

    def __repr__(self):
        return "CTxIn(prevout=%s scriptSig=%s nSequence=%i)" % (
            repr(self.prevout),
            self.scriptSig.hex(),
            self.nSequence,
        )


class CTxOut:
    """Transaction output."""

    __slots__ = ("nValue", "scriptPubKey")

    def __init__(self, nValue=0, scriptPubKey=b""):
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey

    def deserialize(self, f):
        self.nValue = int.from_bytes(f.read(8), "little", signed=True)
        self.scriptPubKey = deser_string(f)

    def serialize(self):
        r = self.nValue.to_bytes(8, "little", signed=True)
        r += ser_string(self.scriptPubKey)
        return r

    def __repr__(self):
        return "CTxOut(nValue=%i.%08i scriptPubKey=%s)" % (
            self.nValue // COIN,
            self.nValue % COIN,
            self.scriptPubKey.hex(),
        )


class CScriptWitness:
    """Witness stack for a single input."""

    __slots__ = ("stack",)

    def __init__(self):
        self.stack = []

    def __repr__(self):
        return "CScriptWitness(%s)" % (",".join([x.hex() for x in self.stack]))

    def is_null(self):
        return not self.stack


class CTxInWitness:
    """Witness data for a transaction input."""

    __slots__ = ("scriptWitness",)

    def __init__(self):
        self.scriptWitness = CScriptWitness()

    def deserialize(self, f):
        self.scriptWitness.stack = deser_string_vector(f)

    def serialize(self):
        return ser_string_vector(self.scriptWitness.stack)

    def __repr__(self):
        return repr(self.scriptWitness)

    def is_null(self):
        return self.scriptWitness.is_null()


class CTxWitness:
    """Witness data for all inputs in a transaction."""

    __slots__ = ("vtxinwit",)

    def __init__(self):
        self.vtxinwit = []

    def deserialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].deserialize(f)

    def serialize(self):
        r = b""
        for x in self.vtxinwit:
            r += x.serialize()
        return r

    def __repr__(self):
        return "CTxWitness(%s)" % (";".join([repr(x) for x in self.vtxinwit]))

    def is_null(self):
        for x in self.vtxinwit:
            if not x.is_null():
                return False
        return True


class CTransaction:
    """Bitcoin transaction."""

    __slots__ = ("nLockTime", "version", "vin", "vout", "wit")

    def __init__(self, tx=None):
        if tx is None:
            self.version = 2
            self.vin = []
            self.vout = []
            self.wit = CTxWitness()
            self.nLockTime = 0
        else:
            self.version = tx.version
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.wit = copy.deepcopy(tx.wit)

    def deserialize(self, f):
        self.version = int.from_bytes(f.read(4), "little")
        self.vin = deser_vector(f, CTxIn)
        flags = 0
        if len(self.vin) == 0:
            flags = int.from_bytes(f.read(1), "little")
            if flags != 0:
                self.vin = deser_vector(f, CTxIn)
                self.vout = deser_vector(f, CTxOut)
        else:
            self.vout = deser_vector(f, CTxOut)
        if flags != 0:
            self.wit.vtxinwit = [CTxInWitness() for _ in range(len(self.vin))]
            self.wit.deserialize(f)
        else:
            self.wit = CTxWitness()
        self.nLockTime = int.from_bytes(f.read(4), "little")

    def serialize_without_witness(self):
        r = self.version.to_bytes(4, "little")
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        r += self.nLockTime.to_bytes(4, "little")
        return r

    def serialize_with_witness(self):
        flags = 0
        if not self.wit.is_null():
            flags |= 1
        r = self.version.to_bytes(4, "little")
        if flags:
            dummy = []
            r += ser_vector(dummy)
            r += flags.to_bytes(1, "little")
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        if flags & 1:
            if len(self.wit.vtxinwit) != len(self.vin):
                self.wit.vtxinwit = self.wit.vtxinwit[: len(self.vin)]
                for _ in range(len(self.wit.vtxinwit), len(self.vin)):
                    self.wit.vtxinwit.append(CTxInWitness())
            r += self.wit.serialize()
        r += self.nLockTime.to_bytes(4, "little")
        return r

    def serialize(self):
        return self.serialize_with_witness()

    @property
    def wtxid_hex(self):
        """Return wtxid (transaction hash with witness) as hex string."""
        return hash256(self.serialize())[::-1].hex()

    @property
    def wtxid_int(self):
        """Return wtxid (transaction hash with witness) as integer."""
        return uint256_from_str(hash256(self.serialize_with_witness()))

    @property
    def txid_hex(self):
        """Return txid (transaction hash without witness) as hex string."""
        return hash256(self.serialize_without_witness())[::-1].hex()

    @property
    def txid_int(self):
        """Return txid (transaction hash without witness) as integer."""
        return uint256_from_str(hash256(self.serialize_without_witness()))

    def is_valid(self):
        for tout in self.vout:
            if tout.nValue < 0 or tout.nValue > 21000000 * COIN:
                return False
        return True

    def get_weight(self):
        with_witness_size = len(self.serialize_with_witness())
        without_witness_size = len(self.serialize_without_witness())
        return (WITNESS_SCALE_FACTOR - 1) * without_witness_size + with_witness_size

    def get_vsize(self):
        return math.ceil(self.get_weight() / WITNESS_SCALE_FACTOR)

    def __repr__(self):
        return "CTransaction(version=%i vin=%s vout=%s wit=%s nLockTime=%i)" % (
            self.version,
            repr(self.vin),
            repr(self.vout),
            repr(self.wit),
            self.nLockTime,
        )
