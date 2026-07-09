"""
Silent payment output script derivation
"""

from typing import Iterator, List, Optional, Tuple

from deps.bitcoin_test.messages import COutPoint
from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.ecdh import ecdh_compressed_in_raw_out
from secp256k1lab.util import tagged_hash

from .inputs import build_outpoints, collect_input_ecdh_and_pubkey
from .psbt_bip375 import BIP375PSBTMap, PSBT_OUT_SP_V0_INFO


def compute_silent_payment_output_script(
    outpoints: List[COutPoint],
    summed_pubkey_bytes: bytes,
    ecdh_share_bytes: bytes,
    spend_pubkey_bytes: bytes,
    k: int,
) -> bytes:
    """Compute silent payment output script per BIP-352"""
    input_hash_bytes = get_input_hash(outpoints, GE.from_bytes(summed_pubkey_bytes))

    # Compute shared_secret = input_hash * ecdh_share
    shared_secret_bytes = ecdh_compressed_in_raw_out(
        input_hash_bytes, ecdh_share_bytes
    ).to_bytes_compressed()

    # Compute t_k = hash_BIP0352/SharedSecret(shared_secret || k)
    t_k = Scalar.from_bytes_checked(
        tagged_hash("BIP0352/SharedSecret", shared_secret_bytes + ser_uint32(k))
    )

    # Compute P_k = B_spend + t_k * G
    B_spend = GE.from_bytes(spend_pubkey_bytes)
    P_k = B_spend + t_k * G

    # Return P2TR script (x-only pubkey)
    return bytes([0x51, 0x20]) + P_k.to_bytes_xonly()


def get_input_hash(outpoints: List[COutPoint], sum_input_pubkeys: GE) -> bytes:
    """Compute input hash per BIP-352"""
    lowest_outpoint = sorted(outpoints, key=lambda outpoint: outpoint.serialize())[0]
    return tagged_hash(
        "BIP0352/Inputs",
        lowest_outpoint.serialize() + sum_input_pubkeys.to_bytes_compressed(),
    )


def ser_uint32(u: int) -> bytes:
    return u.to_bytes(4, "big")


def derive_sp_output_scripts(
    psbt,
) -> Iterator[Tuple[int, BIP375PSBTMap, Optional[bytes]]]:
    """Yield (output_idx, output_map, computed_script) for every silent payment output.

    k is assigned per scan key in (sp_info, output_idx) sorted order so the produce
    and verify paths agree. computed_script is None when the ECDH share or input
    pubkeys are unavailable; callers decide how to treat that.
    """
    outpoints = build_outpoints(psbt)

    sp_outputs = [
        (output_map[PSBT_OUT_SP_V0_INFO], output_idx, output_map)
        for output_idx, output_map in enumerate(psbt.o)
        if PSBT_OUT_SP_V0_INFO in output_map
    ]
    sp_outputs.sort(key=lambda entry: (entry[0], entry[1]))

    scan_key_k_values = {}
    for sp_info, output_idx, output_map in sp_outputs:
        scan_key = sp_info[:33]
        spend_key = sp_info[33:]
        k = scan_key_k_values.get(scan_key, 0)

        ecdh_share_bytes, summed_pubkey_bytes = collect_input_ecdh_and_pubkey(
            psbt, scan_key
        )

        if ecdh_share_bytes and summed_pubkey_bytes and outpoints:
            script = compute_silent_payment_output_script(
                outpoints, summed_pubkey_bytes, ecdh_share_bytes, spend_key, k
            )
            scan_key_k_values[scan_key] = k + 1
            yield output_idx, output_map, script
        else:
            yield output_idx, output_map, None
