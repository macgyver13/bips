#!/usr/bin/env python3
"""BIP-375 Signer, up to but not including transaction signatures.

Verifies the PSBT and other signers' DLEQ proofs, adds this signer's ECDH
shares and DLEQ proofs, and sets PSBT_OUT_SCRIPT once every eligible input is
covered. Transaction signatures stay with the wallet that holds a signer.
"""

import secrets

from deps.bitcoin_test.psbt import PSBT_GLOBAL_TX_MODIFIABLE, PSBT_OUT_SCRIPT
from deps.dleq import dleq_generate_proof
from secp256k1lab.secp256k1 import G, GE
from validator.inputs import (
    is_input_eligible,
    is_p2tr,
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

INPUTS_MODIFIABLE = 0x01
OUTPUTS_MODIFIABLE = 0x02


def sign_sp_psbt(
    psbt: BIP375PSBT,
    input_private_keys: list[tuple[int, bytes]],
    dleq_aux_rand: dict[tuple[bytes, int | None], bytes] | None = None,
) -> BIP375PSBT:
    """Follow the BIP-375 Signer rules through the output scripts.

    input_private_keys is (input index, private key) for each input this signer
    holds. dleq_aux_rand maps (scan key, input index) to 32 bytes of proof
    randomness. input index None is the global share. Without an entry, fresh
    randomness is drawn and the proof will not match a published vector.
    """
    _verify_for_signer(psbt)
    _add_ecdh_shares(psbt, input_private_keys, dleq_aux_rand or {})
    if not _sp_output_scripts_set(psbt) and _has_full_ecdh_coverage(psbt):
        _set_sp_output_scripts(psbt)
    return psbt


def _verify_for_signer(psbt: BIP375PSBT) -> None:
    ok, msg, _ = run_checks(psbt)
    if not ok:
        raise ValueError(f"Signer verification failed: {msg}")


def _add_ecdh_shares(
    psbt: BIP375PSBT,
    input_private_keys: list[tuple[int, bytes]],
    dleq_aux_rand: dict[tuple[bytes, int | None], bytes],
) -> None:
    scan_keys = sp_scan_keys(psbt)
    eligible = {idx for idx, inp in enumerate(psbt.i) if is_input_eligible(inp, idx)}
    held = [(idx, key) for idx, key in input_private_keys if idx in eligible]
    if not scan_keys or not held:
        return

    privkeys = {
        idx: _normalized_input_privkey(psbt.i[idx], idx, int.from_bytes(key, "big"))
        for idx, key in held
    }

    if privkeys.keys() == eligible:
        a_sum = sum(privkeys.values()) % GE.ORDER
        for scan_key in scan_keys:
            if scan_key_is_covered(psbt, scan_key):
                continue
            ecdh_share, proof = _create_ecdh_share_and_proof(
                a_sum, scan_key, dleq_aux_rand.get((scan_key, None))
            )
            psbt.g.set_by_key(PSBT_GLOBAL_SP_ECDH_SHARE, scan_key, ecdh_share)
            psbt.g.set_by_key(PSBT_GLOBAL_SP_DLEQ, scan_key, proof)
        return

    for idx, scalar in privkeys.items():
        input_map = psbt.i[idx]
        for scan_key in scan_keys:
            if input_map.get_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key):
                continue
            ecdh_share, proof = _create_ecdh_share_and_proof(
                scalar, scan_key, dleq_aux_rand.get((scan_key, idx))
            )
            input_map.set_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key, ecdh_share)
            input_map.set_by_key(PSBT_IN_SP_DLEQ, scan_key, proof)


def _normalized_input_privkey(input_map: BIP375PSBTMap, index: int, scalar: int) -> int:
    """A taproot key is negated when its point has odd Y (BIP-352)."""
    script = script_pubkey_from_psbt_input(input_map, index)
    if is_p2tr(script) and not (scalar * G).has_even_y():
        return GE.ORDER - scalar
    return scalar


def _create_ecdh_share_and_proof(scalar: int, scan_key: bytes, aux_rand: bytes | None):
    point = GE.from_bytes(scan_key)
    randomness = aux_rand if aux_rand is not None else secrets.token_bytes(32)
    proof = dleq_generate_proof(scalar, point, randomness)
    if proof is None:
        raise ValueError("Failed to generate DLEQ proof")
    return (scalar * point).to_bytes_compressed(), proof


def _sp_output_scripts_set(psbt: BIP375PSBT) -> bool:
    return all(PSBT_OUT_SCRIPT in output for output in psbt.o if PSBT_OUT_SP_V0_INFO in output)


def _has_full_ecdh_coverage(psbt: BIP375PSBT) -> bool:
    return all(scan_key_is_covered(psbt, scan_key) for scan_key in sp_scan_keys(psbt))


def _set_sp_output_scripts(psbt: BIP375PSBT) -> None:
    for output_idx, output_map, script in derive_sp_output_scripts(psbt):
        if script is None:
            raise ValueError(f"Cannot compute output {output_idx} script")
        output_map[PSBT_OUT_SCRIPT] = script
    flags = psbt.g.get(PSBT_GLOBAL_TX_MODIFIABLE)
    value = flags[0] if flags else 0
    psbt.g[PSBT_GLOBAL_TX_MODIFIABLE] = bytes([value & ~(INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE)])
