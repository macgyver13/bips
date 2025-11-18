import hashlib
import struct
from io import BytesIO
from secp256k1_374 import GE, G
from ripemd160 import ripemd160
from typing import Union, List, Tuple


def from_hex(hex_string):
    """Deserialize from a hex string representation (e.g. from RPC)"""
    return BytesIO(bytes.fromhex(hex_string))


def ser_uint32(u: int) -> bytes:
    return u.to_bytes(4, "big")


def ser_uint256(u):
    return u.to_bytes(32, "little")


def deser_uint256(f):
    return int.from_bytes(f.read(32), "little")


def deser_txid(txid: str):
    # recall that txids are serialized little-endian, but displayed big-endian
    # this means when converting from a human readable hex txid, we need to first
    # reverse it before deserializing it
    dixt = "".join(map(str.__add__, txid[-2::-2], txid[-1::-2]))
    return bytes.fromhex(dixt)


def deser_compact_size(f: BytesIO):
    view = f.getbuffer()
    nbytes = view.nbytes
    view.release()
    if nbytes == 0:
        return 0  # end of stream

    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit


def deser_string(f: BytesIO):
    nit = deser_compact_size(f)
    return f.read(nit)


def deser_string_vector(f: BytesIO):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_string(f)
        r.append(t)
    return r


def hash160(s: Union[bytes, bytearray]) -> bytes:
    return ripemd160(hashlib.sha256(s).digest())


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


def is_eligible_input_type(script_pubkey: bytes) -> bool:
    """Check if scriptPubKey is an eligible input type for silent payments per BIP-352"""
    return (
        is_p2pkh(script_pubkey)
        or is_p2wpkh(script_pubkey)
        or is_p2tr(script_pubkey)
        or is_p2sh(script_pubkey)
    )


def parse_non_witness_utxo(non_witness_utxo: bytes, output_index: int) -> bytes:
    """Extract scriptPubKey from NON_WITNESS_UTXO field"""
    try:
        offset = 0

        # Skip version (4 bytes)
        if len(non_witness_utxo) < 4:
            return None
        offset += 4

        # Parse input count (compact size)
        if offset >= len(non_witness_utxo):
            return None

        input_count = non_witness_utxo[offset]
        offset += 1
        if input_count >= 0xFD:
            # Handle larger compact size (simplified - just skip)
            if input_count == 0xFD:
                offset += 2
            elif input_count == 0xFE:
                offset += 4
            else:
                offset += 8
            input_count = (
                struct.unpack("<H", non_witness_utxo[offset - 2 : offset])[0]
                if input_count == 0xFD
                else 0
            )

        # Skip all inputs
        for _ in range(input_count):
            # Skip txid (32) + vout (4)
            offset += 36
            if offset >= len(non_witness_utxo):
                return None

            # Skip scriptSig
            script_len = non_witness_utxo[offset]
            offset += 1
            if script_len >= 0xFD:
                return None  # Simplified - don't handle large scripts
            offset += script_len

            # Skip sequence (4)
            offset += 4
            if offset > len(non_witness_utxo):
                return None

        # Parse output count
        if offset >= len(non_witness_utxo):
            return None
        output_count = non_witness_utxo[offset]
        offset += 1
        if output_count >= 0xFD:
            if output_count == 0xFD:
                output_count = struct.unpack(
                    "<H", non_witness_utxo[offset : offset + 2]
                )[0]
                offset += 2
            else:
                return None  # Simplified

        # Find the output at output_index
        for i in range(output_count):
            # Skip amount (8 bytes)
            if offset + 8 >= len(non_witness_utxo):
                return None
            offset += 8

            # Parse scriptPubKey length
            if offset >= len(non_witness_utxo):
                return None
            script_len = non_witness_utxo[offset]
            offset += 1
            if script_len >= 0xFD:
                if script_len == 0xFD:
                    script_len = struct.unpack(
                        "<H", non_witness_utxo[offset : offset + 2]
                    )[0]
                    offset += 2
                else:
                    return None

            # Extract scriptPubKey if this is our output
            if i == output_index:
                if offset + script_len > len(non_witness_utxo):
                    return None
                return non_witness_utxo[offset : offset + script_len]

            # Otherwise skip to next output
            offset += script_len
            if offset > len(non_witness_utxo):
                return None

        return None
    except Exception:
        return None


def compute_bip352_output_script(
    outpoints: List[Tuple[bytes, int]],
    summed_pubkey_bytes: bytes,
    ecdh_share_bytes: bytes,
    spend_pubkey_bytes: bytes,
    k: int = 0,
) -> bytes:
    """Compute BIP-352 silent payment output script"""
    # Find smallest outpoint lexicographically
    serialized_outpoints = [txid + struct.pack("<I", idx) for txid, idx in outpoints]
    smallest_outpoint = min(serialized_outpoints)

    # Compute input_hash = hash_BIP0352/Inputs(smallest_outpoint || A)
    tag_data = b"BIP0352/Inputs"
    tag_hash = hashlib.sha256(tag_data).digest()
    input_hash_preimage = tag_hash + tag_hash + smallest_outpoint + summed_pubkey_bytes
    input_hash_bytes = hashlib.sha256(input_hash_preimage).digest()
    input_hash = int.from_bytes(input_hash_bytes, "big")

    # Compute shared_secret = input_hash * ecdh_share
    ecdh_point = GE.from_bytes(ecdh_share_bytes)
    shared_secret_point = input_hash * ecdh_point
    shared_secret_bytes = shared_secret_point.to_bytes_compressed()

    # Compute t_k = hash_BIP0352/SharedSecret(shared_secret || k)
    tag_data = b"BIP0352/SharedSecret"
    tag_hash = hashlib.sha256(tag_data).digest()
    t_preimage = tag_hash + tag_hash + shared_secret_bytes + k.to_bytes(4, "big")
    t_k_bytes = hashlib.sha256(t_preimage).digest()
    t_k = int.from_bytes(t_k_bytes, "big")

    # Compute P_k = B_spend + t_k * G
    B_spend = GE.from_bytes(spend_pubkey_bytes)
    P_k = B_spend + (t_k * G)

    # Create P2TR script (x-only pubkey)
    x_only = P_k.to_bytes_compressed()[1:]  # Remove parity byte
    return bytes([0x51, 0x20]) + x_only
