#!/usr/bin/env python3
"""
Signing utilities for PSBT workflow.

Adapted from Bitcoin Core test framework key.py
(Copyright (c) 2019-2020 Pieter Wuille, MIT License)

WARNING: This code is for testing only. Do not use for anything
requiring security.
"""

import hashlib
import hmac
import random

from secp256k1lab.secp256k1 import GE, G


# Order of the secp256k1 curve
ORDER = GE.ORDER


def tagged_hash(tag: str, data: bytes) -> bytes:
    """Compute BIP-340 tagged hash."""
    ss = hashlib.sha256(tag.encode("utf-8")).digest()
    ss += ss
    ss += data
    return hashlib.sha256(ss).digest()


def rfc6979_nonce(key: bytes, msg: bytes) -> bytes:
    """Compute signing nonce using RFC6979."""
    v = bytes([1] * 32)
    k = bytes([0] * 32)
    k = hmac.new(k, v + b"\x00" + key + msg, "sha256").digest()
    v = hmac.new(k, v, "sha256").digest()
    k = hmac.new(k, v + b"\x01" + key + msg, "sha256").digest()
    v = hmac.new(k, v, "sha256").digest()
    return hmac.new(k, v, "sha256").digest()


def compute_xonly_pubkey(key: bytes) -> tuple:
    """
    Compute x-only (32-byte) public key from a 32-byte private key.

    Returns:
        Tuple of (xonly_pubkey, was_negated)
    """
    assert len(key) == 32
    x = int.from_bytes(key, "big")
    if x == 0 or x >= ORDER:
        return (None, None)
    P = x * G
    return (P.to_bytes_xonly(), not P.y.is_even())


class ECKey:
    """A secp256k1 private key for ECDSA signing."""

    def __init__(self):
        self.valid = False
        self.secret = None
        self.compressed = True

    def set(self, secret: bytes, compressed: bool = True):
        """Construct a private key from 32-byte secret."""
        assert len(secret) == 32
        secret_int = int.from_bytes(secret, "big")
        self.valid = 0 < secret_int < ORDER
        if self.valid:
            self.secret = secret_int
            self.compressed = compressed

    def generate(self, compressed: bool = True):
        """Generate a random private key."""
        self.set(random.randrange(1, ORDER).to_bytes(32, "big"), compressed)

    def get_bytes(self) -> bytes:
        """Get 32-byte representation of this key."""
        assert self.valid
        return self.secret.to_bytes(32, "big")

    @property
    def is_valid(self) -> bool:
        return self.valid

    @property
    def is_compressed(self) -> bool:
        return self.compressed

    def get_pubkey(self) -> "ECPubKey":
        """Compute ECPubKey object for this secret key."""
        assert self.valid
        ret = ECPubKey()
        ret.p = self.secret * G
        ret.compressed = self.compressed
        return ret

    def sign_ecdsa(
        self, msg: bytes, low_s: bool = True, rfc6979: bool = False
    ) -> bytes:
        """
        Construct a DER-encoded ECDSA signature.

        Args:
            msg: 32-byte message hash to sign
            low_s: Enforce low-s (BIP-62)
            rfc6979: Use deterministic nonce (default: random for test diversity)

        Returns:
            DER-encoded ECDSA signature
        """
        assert self.valid
        z = int.from_bytes(msg, "big")

        if rfc6979:
            k = int.from_bytes(
                rfc6979_nonce(self.secret.to_bytes(32, "big"), msg), "big"
            )
        else:
            k = random.randrange(1, ORDER)

        R = k * G
        r = int(R.x) % ORDER
        s = (pow(k, -1, ORDER) * (z + self.secret * r)) % ORDER

        if low_s and s > ORDER // 2:
            s = ORDER - s

        # DER encoding
        rb = r.to_bytes((r.bit_length() + 8) // 8, "big")
        sb = s.to_bytes((s.bit_length() + 8) // 8, "big")
        return (
            b"\x30"
            + bytes([4 + len(rb) + len(sb), 2, len(rb)])
            + rb
            + bytes([2, len(sb)])
            + sb
        )


class ECPubKey:
    """A secp256k1 public key."""

    def __init__(self):
        self.p = None
        self.compressed = True

    def set(self, data: bytes):
        """Construct from serialization (compressed or uncompressed)."""
        self.p = GE.from_bytes(data)
        self.compressed = len(data) == 33

    @property
    def is_valid(self) -> bool:
        return self.p is not None

    @property
    def is_compressed(self) -> bool:
        return self.compressed

    def get_bytes(self) -> bytes:
        """Get serialized form."""
        assert self.is_valid
        if self.compressed:
            return self.p.to_bytes_compressed()
        else:
            return self.p.to_bytes_uncompressed()

    def verify_ecdsa(self, sig: bytes, msg: bytes, low_s: bool = True) -> bool:
        """
        Verify a DER-encoded ECDSA signature.

        Args:
            sig: DER-encoded signature
            msg: 32-byte message hash
            low_s: Enforce low-s (BIP-62)

        Returns:
            True if signature is valid
        """
        assert self.is_valid

        # Parse DER signature
        if len(sig) < 4 or sig[0] != 0x30:
            return False
        if sig[1] + 2 != len(sig):
            return False
        if sig[2] != 0x02:
            return False

        rlen = sig[3]
        if len(sig) < 6 + rlen:
            return False
        if rlen < 1 or rlen > 33:
            return False
        if sig[4] >= 0x80:
            return False
        if rlen > 1 and sig[4] == 0 and not (sig[5] & 0x80):
            return False

        r = int.from_bytes(sig[4 : 4 + rlen], "big")

        if sig[4 + rlen] != 0x02:
            return False

        slen = sig[5 + rlen]
        if slen < 1 or slen > 33:
            return False
        if len(sig) != 6 + rlen + slen:
            return False
        if sig[6 + rlen] >= 0x80:
            return False
        if slen > 1 and sig[6 + rlen] == 0 and not (sig[7 + rlen] & 0x80):
            return False

        s = int.from_bytes(sig[6 + rlen : 6 + rlen + slen], "big")

        # Verify r, s are in range
        if r < 1 or s < 1 or r >= ORDER or s >= ORDER:
            return False
        if low_s and s >= ORDER // 2:
            return False

        z = int.from_bytes(msg, "big")

        # ECDSA verification
        w = pow(s, -1, ORDER)
        u1 = (z * w) % ORDER
        u2 = (r * w) % ORDER
        R = GE.batch_mul((u1, G), (u2, self.p))
        if R.infinity or (int(R.x) % ORDER) != r:
            return False
        return True
