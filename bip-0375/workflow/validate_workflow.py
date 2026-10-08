#!/usr/bin/env python3
"""
Drive the reference roles against the BIP-375 test vectors.

Every `valid` vector and every `workflows` step names a task. run_vector
validates the incoming `psbt`, runs the role the task names, and compares the
result to `expected.psbt` field by field (for `extract`, the raw transaction to
`expected.tx`). A `create` step builds its PSBT from `supplementary` alone, and
a `deserialize` vector is validated only.
"""

import traceback

from validator.psbt_bip375 import BIP375PSBT
from validator.validate_psbt import run_checks
from workflow.roles import (
    construct_sp_psbt,
    create_psbt,
    extract_sp_transaction,
    finalize_sp_inputs,
    sign_sp_psbt,
    transaction_id,
    update_sp_psbt,
)


def _create(supplementary: dict) -> BIP375PSBT:
    """Creator and Constructor: the inputs and outputs come from supplementary"""
    inputs = [
        {
            # prevout_txid is in display (RPC) byte order; PSBT_IN_PREVIOUS_TXID is
            # internal byte order
            "txid": bytes.fromhex(inp["prevout_txid"])[::-1],
            "vout": inp["prevout_index"],
            "sequence": inp["sequence"],
        }
        for inp in supplementary["inputs"]
    ]
    sp_outputs, regular_outputs = [], []
    for out in supplementary["outputs"]:
        if "sp_v0_info" in out:
            sp_info = bytes.fromhex(out["sp_v0_info"])
            sp_outputs.append(
                {"scan_key": sp_info[:33], "spend_key": sp_info[33:], "amount": out["amount"]}
            )
        else:
            regular_outputs.append(
                {"script": bytes.fromhex(out["script"]), "amount": out["amount"]}
            )
    return construct_sp_psbt(create_psbt(), inputs, sp_outputs, regular_outputs)


def _update(psbt: BIP375PSBT, supplementary: dict) -> BIP375PSBT:
    """Updater: the UTXOs and BIP32 derivations come from supplementary.inputs"""
    inputs = supplementary["inputs"]
    utxos = [
        {"witness_utxo": bytes.fromhex(inp["witness_utxo"])}
        if "witness_utxo" in inp
        else {"non_witness_utxo": bytes.fromhex(inp["non_witness_utxo"])}
        for inp in inputs
    ]
    # A vector whose keys come from a seeded wallet discloses their origin;
    # otherwise the Updater withholds it (zero fingerprint, empty path)
    derivations = [
        {
            "pubkey": bytes.fromhex(inp["public_key"]),
            "fingerprint": bytes.fromhex(inp.get("master_fingerprint", "00000000")),
            "path": inp.get("derivation_path", []),
        }
        for inp in inputs
    ]
    return update_sp_psbt(psbt, utxos, derivations)


def _sign(psbt: BIP375PSBT, supplementary: dict) -> BIP375PSBT:
    """Signer: acts for every input whose private key the vector discloses.

    The first Signer of a per-input share workflow contributes a share but cannot
    sign yet; sign_sp_psbt decides that from whether the output scripts are set.
    supplementary.dleq_aux_rand discloses the randomness each DLEQ proof the step
    contributes must use, so the Signer's own proofs are compared to expected.psbt
    like every other field.
    """
    held = [
        (inp["input_index"], bytes.fromhex(inp["private_key"]))
        for inp in supplementary["inputs"]
        if inp.get("private_key")
    ]
    aux_rand = {
        (bytes.fromhex(entry["scan_key"]), entry.get("input_index")): bytes.fromhex(entry["aux_rand"])
        for entry in supplementary.get("dleq_aux_rand", [])
    }
    return sign_sp_psbt(psbt, held, aux_rand)


_ROLES = {
    "update": _update,
    "sign": _sign,
    "finalize": lambda psbt, _supplementary: finalize_sp_inputs(psbt),
}


def run_vector(vector: dict) -> list[str]:
    """Run one vector through the role its task names. Returns the failures; an
    empty list means it passed."""
    supplementary = vector["supplementary"]
    task = supplementary["task"]
    expected = vector.get("expected", {})

    if task == "create":
        result = _create(supplementary)
    else:
        incoming = BIP375PSBT.from_base64(vector["psbt"])
        ok, msg, check = run_checks(incoming, vector.get("checks"))
        if not ok:
            return [f"incoming psbt fails {check}: {msg}"]
        if task == "deserialize":
            return []
        if task == "extract":
            failures = _transaction_id_failures(incoming, expected)
            got_tx = extract_sp_transaction(incoming).serialize().hex()
            if got_tx != expected["tx"]:
                failures.append(f"extracted tx differs: got {got_tx} expected {expected['tx']}")
            return failures
        if task not in _ROLES:
            return [f"unknown task '{task}'"]
        result = _ROLES[task](incoming, supplementary)

    failures = _map_field_diffs(result, BIP375PSBT.from_base64(expected["psbt"]))
    failures += _transaction_id_failures(result, expected)
    if failures:
        return failures

    ok, msg, check = run_checks(result)
    if not ok:
        return [f"result fails {check}: {msg}"]
    if task == "finalize":
        # The Input Finalizer prunes the fields the checks otherwise read, so the
        # Extractor has to verify a finalized PSBT from what is left
        extract_sp_transaction(result)
    return []


def run_vectors(vectors: list, verbose: bool = False) -> tuple[int, int]:
    """Run each vector, printing its description and any failures"""
    passed = failed = 0
    for vector in vectors:
        print(vector["description"])
        task = vector.get("supplementary", {}).get("task")
        try:
            failures = run_vector(vector)
        except Exception as e:
            failures = [f"{type(e).__name__}: {e}"]
            if verbose:
                traceback.print_exc()

        if failures:
            failed += 1
            print(f"  {task}: FAILED")
            for failure in failures:
                print(f"    {failure}")
        else:
            passed += 1
            if verbose:
                print(f"  {task}: PASSED")
    return passed, failed


def _transaction_id_failures(psbt: BIP375PSBT, expected: dict) -> list[str]:
    """Check the BIP-375 unique identifier against expected.transaction_id, which
    every step of a workflow shares, so no role may change it"""
    expected_id = expected.get("transaction_id")
    if expected_id is None:
        return []
    got = transaction_id(psbt)
    if got != expected_id:
        return [f"transaction_id mismatch: got {got} expected {expected_id}"]
    return []


def _map_field_diffs(got_psbt: BIP375PSBT, exp_psbt: BIP375PSBT) -> list[str]:
    """Compare PSBT maps field by field. PSBT field order is not significant, so
    the maps are compared as dicts, never as raw bytes."""
    diffs = []
    _diff_map(got_psbt.g.map, exp_psbt.g.map, "global", diffs)
    if len(got_psbt.i) != len(exp_psbt.i):
        diffs.append(f"input count: got {len(got_psbt.i)} expected {len(exp_psbt.i)}")
    if len(got_psbt.o) != len(exp_psbt.o):
        diffs.append(f"output count: got {len(got_psbt.o)} expected {len(exp_psbt.o)}")
    for idx, (got, exp) in enumerate(zip(got_psbt.i, exp_psbt.i)):
        _diff_map(got.map, exp.map, f"input[{idx}]", diffs)
    for idx, (got, exp) in enumerate(zip(got_psbt.o, exp_psbt.o)):
        _diff_map(got.map, exp.map, f"output[{idx}]", diffs)
    return diffs


def _diff_map(got: dict, exp: dict, label: str, diffs: list) -> None:
    for key in got.keys() - exp.keys():
        diffs.append(f"{label}: field {_fmt_key(key)} only in got = {got[key].hex()}")
    for key in exp.keys() - got.keys():
        diffs.append(f"{label}: field {_fmt_key(key)} only in expected = {exp[key].hex()}")
    for key in got.keys() & exp.keys():
        if got[key] != exp[key]:
            diffs.append(
                f"{label}: field {_fmt_key(key)} differs: "
                f"got {got[key].hex()} expected {exp[key].hex()}"
            )


def _fmt_key(key) -> str:
    """Render a PSBT map key as type[+key_data]. A key with no key_data is stored
    as an int; a longer key is the key_type byte followed by key_data."""
    if isinstance(key, int):
        return f"0x{key:02x}"
    return f"0x{key[0]:02x}+{key[1:].hex()}"
