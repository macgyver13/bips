#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Serialization and utility functions for Bitcoin transactions.
"""

import hashlib
from io import BytesIO
import struct


def sha256(s: bytes) -> bytes:
    """Single SHA256 hash."""
    return hashlib.sha256(s).digest()


def hash256(s: bytes) -> bytes:
    """Double SHA256 hash."""
    return sha256(sha256(s))


def hash160(s: bytes) -> bytes:
    """HASH160 (SHA256 then RIPEMD160)."""
    return hashlib.new("ripemd160", sha256(s)).digest()


# like from_hex, but without the hex part
def from_binary(cls, stream):
    """deserialize a binary stream (or bytes object) into an object"""
    # handle bytes object by turning it into a stream
    was_bytes = isinstance(stream, bytes)
    if was_bytes:
        stream = BytesIO(stream)
    obj = cls()
    obj.deserialize(stream)
    if was_bytes:
        assert len(stream.read()) == 0
    return obj


def ser_compact_size(size: int) -> bytes:
    """Serialize a compact size uint"""
    if size < 0xFD:
        return bytes([size])
    elif size <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", size)
    elif size <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<L", size)
    else:
        return b"\xff" + struct.pack("<Q", size)

def deser_compact_size(f):
    nit = int.from_bytes(f.read(1), "little")
    if nit == 253:
        nit = int.from_bytes(f.read(2), "little")
    elif nit == 254:
        nit = int.from_bytes(f.read(4), "little")
    elif nit == 255:
        nit = int.from_bytes(f.read(8), "little")
    return nit


def deser_string(f) -> bytes:
    """Deserialize a length-prefixed byte string"""
    size_byte = f.read(1)
    if len(size_byte) == 0:
        return b""

    size = size_byte[0]
    if size == 0xFD:
        size = struct.unpack("<H", f.read(2))[0]
    elif size == 0xFE:
        size = struct.unpack("<L", f.read(4))[0]
    elif size == 0xFF:
        size = struct.unpack("<Q", f.read(8))[0]

    return f.read(size)


def is_p2tr(spk: bytes) -> bool:
    if len(spk) != 34:
        return False
    # OP_1 OP_PUSHBYTES_32 <32 bytes>
    return (spk[0] == 0x51) & (spk[1] == 0x20)


def is_p2wpkh(spk: bytes) -> bool:
    if len(spk) != 22:
        return False
    # OP_0 OP_PUSHBYTES_20 <20 bytes>
    return (spk[0] == 0x00) & (spk[1] == 0x14)


def is_p2sh(spk: bytes) -> bool:
    if len(spk) != 23:
        return False
    # OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUAL
    return (spk[0] == 0xA9) & (spk[1] == 0x14) & (spk[-1] == 0x87)


def is_p2pkh(spk: bytes) -> bool:
    if len(spk) != 25:
        return False
    # OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return (
        (spk[0] == 0x76)
        & (spk[1] == 0xA9)
        & (spk[2] == 0x14)
        & (spk[-2] == 0x88)
        & (spk[-1] == 0xAC)
    )


def deser_compact_size(f: BytesIO) -> int:
    """Deserialize a compact size integer."""
    nit = int.from_bytes(f.read(1), "little")
    if nit == 253:
        nit = int.from_bytes(f.read(2), "little")
    elif nit == 254:
        nit = int.from_bytes(f.read(4), "little")
    elif nit == 255:
        nit = int.from_bytes(f.read(8), "little")
    return nit


def ser_string(s: bytes) -> bytes:
    """Serialize a variable-length byte string."""
    return ser_compact_size(len(s)) + s


def ser_uint256(u: int) -> bytes:
    """Serialize a 256-bit integer (little-endian)."""
    return u.to_bytes(32, "little")


def deser_uint256(f: BytesIO) -> int:
    """Deserialize a 256-bit integer (little-endian)."""
    return int.from_bytes(f.read(32), "little")


def uint256_from_str(s: bytes) -> int:
    """Convert 32-byte string to uint256."""
    return int.from_bytes(s[:32], "little")


def ser_vector(items: list, ser_function_name: str = None) -> bytes:
    """Serialize a vector of objects."""
    r = ser_compact_size(len(items))
    for item in items:
        if ser_function_name:
            r += getattr(item, ser_function_name)()
        else:
            r += item.serialize()
    return r


def deser_vector(f: BytesIO, c, deser_function_name: str = None) -> list:
    """Deserialize a vector of objects."""
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = c()
        if deser_function_name:
            getattr(t, deser_function_name)(f)
        else:
            t.deserialize(f)
        r.append(t)
    return r


def ser_string_vector(items: list) -> bytes:
    """Serialize a vector of strings."""
    r = ser_compact_size(len(items))
    for sv in items:
        r += ser_string(sv)
    return r


def deser_string_vector(f: BytesIO) -> list:
    """Deserialize a vector of strings."""
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_string(f)
        r.append(t)
    return r
