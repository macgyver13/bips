# Copyright (c) 2019-2020 Pieter Wuille
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test-only secp256k1 elliptic curve protocols implementation

WARNING: This code is slow, uses bad randomness, does not properly protect
keys, and is trivially vulnerable to side channel attacks. Do not use for
anything but tests."""
#
# Trimmed from Bitcoin Core test/functional/test_framework/key.py at 7988380da9
# for the BIP-375 reference. Every definition below is verbatim from that
# file; definitions it does not need are removed. Changed: the imports
# (secp256k1lab for test_framework.crypto.secp256k1). ECPubKey.set and
# ECPubKey.verify_ecdsa are removed because they depend on Core's curve module:
# it returns None for an invalid point where secp256k1lab raises, and has
# GE.mul where secp256k1lab has a GE.batch_mul that does not reduce its scalars.
#

import hashlib
import hmac
import random

from secp256k1lab import secp256k1
from .util import assert_equal

# Order of the secp256k1 curve
ORDER = secp256k1.GE.ORDER

def TaggedHash(tag, data):
    ss = hashlib.sha256(tag.encode('utf-8')).digest()
    ss += ss
    ss += data
    return hashlib.sha256(ss).digest()


class ECPubKey:
    """A secp256k1 public key"""

    def __init__(self):
        """Construct an uninitialized public key"""
        self.p = None

    @property
    def is_compressed(self):
        return self.compressed

    @property
    def is_valid(self):
        return self.p is not None

    def get_bytes(self):
        assert self.is_valid
        if self.compressed:
            return self.p.to_bytes_compressed()
        else:
            return self.p.to_bytes_uncompressed()


def rfc6979_nonce(key):
    """Compute signing nonce using RFC6979."""
    v = bytes([1] * 32)
    k = bytes([0] * 32)
    k = hmac.new(k, v + b"\x00" + key, 'sha256').digest()
    v = hmac.new(k, v, 'sha256').digest()
    k = hmac.new(k, v + b"\x01" + key, 'sha256').digest()
    v = hmac.new(k, v, 'sha256').digest()
    return hmac.new(k, v, 'sha256').digest()

class ECKey:
    """A secp256k1 private key"""

    def __init__(self):
        self.valid = False

    def set(self, secret, compressed):
        """Construct a private key object with given 32-byte secret and compressed flag."""
        assert_equal(len(secret), 32)
        secret = int.from_bytes(secret, 'big')
        self.valid = (secret > 0 and secret < ORDER)
        if self.valid:
            self.secret = secret
            self.compressed = compressed

    def get_bytes(self):
        """Retrieve the 32-byte representation of this key."""
        assert self.valid
        return self.secret.to_bytes(32, 'big')

    @property
    def is_valid(self):
        return self.valid

    @property
    def is_compressed(self):
        return self.compressed

    def get_pubkey(self):
        """Compute an ECPubKey object for this secret key."""
        assert self.valid
        ret = ECPubKey()
        ret.p = self.secret * secp256k1.G
        ret.compressed = self.compressed
        return ret

    def sign_ecdsa(self, msg, low_s=True, rfc6979=False):
        """Construct a DER-encoded ECDSA signature with this key.

        See https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm for the
        ECDSA signer algorithm."""
        assert self.valid
        z = int.from_bytes(msg, 'big')
        # Note: no RFC6979 by default, but a simple random nonce (some tests rely on distinct transactions for the same operation)
        if rfc6979:
            k = int.from_bytes(rfc6979_nonce(self.secret.to_bytes(32, 'big') + msg), 'big')
        else:
            k = random.randrange(1, ORDER)
        R = k * secp256k1.G
        r = int(R.x) % ORDER
        s = (pow(k, -1, ORDER) * (z + self.secret * r)) % ORDER
        if low_s and s > secp256k1.GE.ORDER_HALF:
            s = ORDER - s
        # Represent in DER format. The byte representations of r and s have
        # length rounded up (255 bits becomes 32 bytes and 256 bits becomes 33
        # bytes).
        rb = r.to_bytes((r.bit_length() + 8) // 8, 'big')
        sb = s.to_bytes((s.bit_length() + 8) // 8, 'big')
        return b'\x30' + bytes([4 + len(rb) + len(sb), 2, len(rb)]) + rb + bytes([2, len(sb)]) + sb
