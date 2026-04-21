#!/usr/bin/env python3
"""
Execute step-by-step workflow tests for BIP-375 PSBT test vectors.

Each entry in the `workflows` list is one role transition. The runner takes the
incoming PSBT from top-level `psbt`, applies the role function, and compares the
result to `expected.psbt` semantically. The `transaction` step compares the
extracted raw transaction to `expected.tx`.
"""

import base64
import sys
from pathlib import Path

project_root = Path(__file__).parent
deps_dir = project_root / "deps"
secp256k1lab_dir = deps_dir / "secp256k1lab" / "src"
for path in [str(deps_dir), str(secp256k1lab_dir)]:
    if path not in sys.path:
        sys.path.insert(0, path)

from workflow.roles import (
    create_psbt,
    construct_sp_psbt,
    finalize_sp_outputs,
    sign_sp_psbt,
    finalize_sp_inputs,
    extract_sp_transaction,
    detect_psbt_step,
)
from validator.psbt_bip375 import (
    BIP375PSBT as PSBT,
    PSBT_GLOBAL_SP_ECDH_SHARE,
    PSBT_GLOBAL_SP_DLEQ,
    PSBT_IN_SP_ECDH_SHARE,
    PSBT_IN_SP_DLEQ,
)
from deps.bitcoin_test.psbt import (
    PSBT_IN_WITNESS_UTXO,
    PSBT_IN_BIP32_DERIVATION,
    PSBT_IN_PARTIAL_SIG,
)
from deps.bitcoin_test.signing import ECPubKey
from deps.bitcoin_test.sighash import SegwitV0SignatureHash, make_p2wpkh_script_code, SIGHASH_ALL
from deps.bitcoin_test.transaction import CTxOut
from deps.bitcoin_test.utils import is_p2wpkh, from_binary
from workflow.roles import _build_transaction_from_psbt
from test_runner import validate_bip375_psbt


def _split_sp_v0_info(info_hex: str) -> tuple[bytes, bytes]:
    info = bytes.fromhex(info_hex)
    return info[:33], info[33:66]


def _step_created(_psbt: PSBT | None, _supplementary: dict) -> PSBT:
    return create_psbt()


def _step_constructed(_psbt: PSBT | None, supplementary: dict) -> PSBT:
    # spdk's `create(n, m)` scaffold in top-level `psbt` pre-declares input/
    # output slots; roles.py's Constructor appends slots to an empty PSBT, so
    # we ignore the scaffold and build from a fresh empty PSBT instead.
    psbt = create_psbt()
    inputs = [
        {
            # Vector carries prevout_txid in RPC/display order; PSBT_IN_PREVIOUS_TXID
            # is internal byte order (reversed).
            "txid": bytes.fromhex(i["prevout_txid"])[::-1],
            "vout": i["prevout_index"],
            "sequence": i["sequence"],
        }
        for i in supplementary["inputs"]
    ]
    sp_outputs, regular_outputs = [], []
    for o in supplementary["outputs"]:
        if "sp_v0_info" in o:
            scan_key, spend_key = _split_sp_v0_info(o["sp_v0_info"])
            sp_outputs.append(
                {"scan_key": scan_key, "spend_key": spend_key, "amount": o["amount"]}
            )
        else:
            regular_outputs.append(
                {"script": bytes.fromhex(o["script"]), "amount": o["amount"]}
            )
    return construct_sp_psbt(psbt, inputs, sp_outputs, regular_outputs)


def _step_updated(psbt: PSBT | None, supplementary: dict) -> PSBT:
    """Apply deterministic updater fields and inject pre-computed SP proofs.

    The reference Updater uses fresh randomness for DLEQ proofs, so we cannot
    byte-match by calling update_sp_psbt directly. Instead we install the UTXO,
    BIP32 derivation, and the supplied (ecdh_share, dleq_proof) pair from the
    vector.
    """
    for inp in supplementary["inputs"]:
        input_map = psbt.i[inp["input_index"]]
        input_map[PSBT_IN_WITNESS_UTXO] = bytes.fromhex(inp["witness_utxo"])
        input_map.set_by_key(
            PSBT_IN_BIP32_DERIVATION,
            bytes.fromhex(inp["public_key"]),
            bytes(4),
        )
    for proof in supplementary.get("sp_proofs", []):
        scan_key = bytes.fromhex(proof["scan_key"])
        if "input_index" in proof:
            input_map = psbt.i[proof["input_index"]]
            input_map.set_by_key(
                PSBT_IN_SP_ECDH_SHARE, scan_key, bytes.fromhex(proof["ecdh_share"])
            )
            input_map.set_by_key(
                PSBT_IN_SP_DLEQ, scan_key, bytes.fromhex(proof["dleq_proof"])
            )
        else:
            psbt.g.set_by_key(
                PSBT_GLOBAL_SP_ECDH_SHARE, scan_key, bytes.fromhex(proof["ecdh_share"])
            )
            psbt.g.set_by_key(
                PSBT_GLOBAL_SP_DLEQ, scan_key, bytes.fromhex(proof["dleq_proof"])
            )
    return psbt


def _step_sp_finalized(psbt: PSBT | None, _supplementary: dict) -> PSBT:
    return finalize_sp_outputs(psbt)


def _step_signed(psbt: PSBT | None, supplementary: dict) -> PSBT:
    signers = [
        (inp["input_index"], bytes.fromhex(inp["private_key"]))
        for inp in supplementary["inputs"]
        if inp.get("signed") and "private_key" in inp
    ]
    return sign_sp_psbt(psbt, signers)


def _step_finalized(psbt: PSBT | None, _supplementary: dict) -> PSBT:
    return finalize_sp_inputs(psbt)


STEP_DISPATCH = {
    "create": _step_created,
    "construct": _step_constructed,
    "update": _step_updated,
    "sp_finalize": _step_sp_finalized,
    "sign": _step_signed,
    "finalize": _step_finalized,
}

EXPECTED_STATE_BY_TASK = {
    "create": "created",
    "construct": "constructed",
    "update": "updated",
    "sp_finalize": "sp_finalized",
    "sign": "signed",
    "finalize": "finalized",
}


def _fmt_key(key) -> str:
    """Render a PSBT map key as type[+key_data]. Single-byte keys are stored as
    int (key_type only); longer keys are key_type byte followed by key_data."""
    if isinstance(key, int):
        return f"0x{key:02x}"
    return f"0x{key[0]:02x}+{key[1:].hex()}"


def _diff_map(got: dict, exp: dict, label: str, diffs: list) -> None:
    for key in got.keys() - exp.keys():
        diffs.append(f"{label}: field {_fmt_key(key)} only in got = {got[key].hex()}")
    for key in exp.keys() - got.keys():
        diffs.append(f"{label}: field {_fmt_key(key)} only in expected = {exp[key].hex()}")
    for key in got.keys() & exp.keys():
        if got[key] != exp[key]:
            diffs.append(
                f"{label}: field {_fmt_key(key)} differs — "
                f"got {got[key].hex()} expected {exp[key].hex()}"
            )


def _map_field_diffs(got_psbt: PSBT, exp_psbt: PSBT) -> list:
    """Compare PSBT maps field-by-field. Key/field order is not a PSBT
    requirement, so we compare the maps (dicts) directly, never raw bytes.
    Returns a list of human-readable differences; empty means a match."""
    diffs = []
    _diff_map(got_psbt.g.map, exp_psbt.g.map, "global", diffs)
    if len(got_psbt.i) != len(exp_psbt.i):
        diffs.append(f"input count — got {len(got_psbt.i)} expected {len(exp_psbt.i)}")
    if len(got_psbt.o) != len(exp_psbt.o):
        diffs.append(f"output count — got {len(got_psbt.o)} expected {len(exp_psbt.o)}")
    for idx, (g, x) in enumerate(zip(got_psbt.i, exp_psbt.i)):
        _diff_map(g.map, x.map, f"input[{idx}]", diffs)
    for idx, (g, x) in enumerate(zip(got_psbt.o, exp_psbt.o)):
        _diff_map(g.map, x.map, f"output[{idx}]", diffs)
    return diffs


def _strip_partial_sigs(psbt: PSBT) -> list[list[tuple[bytes, bytes]]]:
    """Remove PSBT_IN_PARTIAL_SIG entries from each input map, returning what was removed.

    Returned shape: [[(pubkey, sig), ...] per input].
    """
    removed = []
    for input_map in psbt.i:
        sigs = input_map.get_all_by_type(PSBT_IN_PARTIAL_SIG)
        for pubkey, _sig in sigs:
            del input_map.map[bytes([PSBT_IN_PARTIAL_SIG]) + pubkey]
        removed.append(sigs)
    return removed


def _compare_signed_step(got_psbt: PSBT, exp_bytes: bytes) -> bool:
    """For the `signed` step, ECDSA signature bytes are non-deterministic across
    RFC6979 implementations (Python vs rust-secp256k1). Strip PSBT_IN_PARTIAL_SIG
    from both sides, compare the remaining map fields, and verify each got
    signature.
    """
    exp_psbt = PSBT.from_base64(base64.b64encode(exp_bytes).decode())
    got_sigs = _strip_partial_sigs(got_psbt)
    _strip_partial_sigs(exp_psbt)

    diffs = _map_field_diffs(got_psbt, exp_psbt)
    if diffs:
        print("  signed: FAILED — non-signature map fields differ:")
        for d in diffs:
            print(f"    {d}")
        return False

    tx = _build_transaction_from_psbt(got_psbt)
    for idx, sigs in enumerate(got_sigs):
        if not sigs:
            continue
        input_map = got_psbt.i[idx]
        witness_utxo = input_map.get(PSBT_IN_WITNESS_UTXO)
        if not witness_utxo:
            print(f"  signed: FAILED — input {idx} missing witness UTXO, cannot verify")
            return False
        utxo = from_binary(CTxOut, witness_utxo)
        if not is_p2wpkh(utxo.scriptPubKey):
            print(f"  signed: FAILED — input {idx} not P2WPKH (verifier only handles P2WPKH)")
            return False
        script_code = make_p2wpkh_script_code(utxo.scriptPubKey[2:])
        sighash = SegwitV0SignatureHash(script_code, tx, idx, SIGHASH_ALL, utxo.nValue)
        for pubkey, sig in sigs:
            if not sig or sig[-1] != SIGHASH_ALL:
                print(f"  signed: FAILED — input {idx} sig has bad sighash byte")
                return False
            pk = ECPubKey()
            pk.set(pubkey)
            if not pk.verify_ecdsa(sig[:-1], sighash):
                print(f"  signed: FAILED — input {idx} signature does not verify")
                return False
    return True


def _run_step(entry: dict, verbose: bool) -> bool:
    task = entry.get("supplementary", {}).get("task", "<missing task>")
    try:
        description = entry.get("description", "")
        expected = entry["expected"]
        supplementary = entry.get("supplementary", {})
        task = supplementary["task"]
        psbt = None if task == "create" else PSBT.from_base64(entry["psbt"])

        if task == "transaction":
            got_tx = extract_sp_transaction(psbt).serialize().hex()
            if got_tx == expected["tx"]:
                print(f"  {task}: PASSED")
                return True
            print(f"  {task}: FAILED — extracted tx differs")
            if verbose:
                print(f"    got:      {got_tx}")
                print(f"    expected: {expected['tx']}")
            return False

        psbt = STEP_DISPATCH[task](psbt, supplementary)
        exp_bytes = base64.b64decode(expected["psbt"])

        if task == "sign":
            if _compare_signed_step(psbt, exp_bytes):
                print(f"  {task}: PASSED ({description})")
                return True
            return False

        exp_psbt = PSBT.from_base64(expected["psbt"])
        diffs = _map_field_diffs(psbt, exp_psbt)
        if not diffs:
            detected = detect_psbt_step(psbt).name.lower()
            is_valid, msg = validate_bip375_psbt(
                base64.b64encode(psbt.serialize()).decode(), checks=None
            )
            expected_state = EXPECTED_STATE_BY_TASK[task]
            step_ok = detected == expected_state
            if step_ok and is_valid:
                print(f"  {task}: PASSED ({description})")
                return True
            print(f"  {task}: FAILED — map fields match but state/validation off")
            if not step_ok:
                print(f"    detected step={detected}, expected={expected_state}")
            if not is_valid:
                print(f"    validation: {msg}")
            return False

        print(f"  {task}: FAILED — map fields differ:")
        for d in diffs:
            print(f"    {d}")
        return False

    except Exception as e:
        print(f"  {task}: ERROR — {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return False


def run_workflow_tests(workflow_data: dict, verbose: bool = False) -> tuple[int, int]:
    """Run every step entry under the top-level `workflows` key."""
    workflows = workflow_data.get("workflows", [])
    passed = 0
    total = 0

    print(f"Workflow steps: {len(workflows)}")
    for entry in workflows:
        total += 1
        if _run_step(entry, verbose):
            passed += 1

    return passed, total - passed
