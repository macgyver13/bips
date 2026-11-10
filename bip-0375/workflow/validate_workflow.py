#!/usr/bin/env python3
"""Silent payment transition checks for valid vectors and workflow steps.

The runner validates each step's PSBTs against the BIP-375 rules and
reproduces only the silent-payment fields. Transaction signatures and final
scripts are taken from expected.psbt as opaque values.
"""

import struct
import traceback
from io import BytesIO

from deps.bitcoin_test.messages import CTransaction
from deps.bitcoin_test.psbt import (
    PSBT_GLOBAL_TX_MODIFIABLE,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_SEQUENCE,
    PSBT_OUT_AMOUNT,
    PSBT_OUT_SCRIPT,
)
from validator.psbt_bip375 import (
    BIP375PSBT,
    PSBT_GLOBAL_SP_DLEQ,
    PSBT_GLOBAL_SP_ECDH_SHARE,
    PSBT_IN_SP_DLEQ,
    PSBT_IN_SP_ECDH_SHARE,
    PSBT_OUT_SP_V0_INFO,
    PSBT_OUT_SP_V0_LABEL,
    ValidationError,
)
from validator.inputs import is_input_eligible
from validator.validate_psbt import run_checks
from workflow.sp_signer import sign_sp_psbt

SP_GLOBAL_TYPES = {PSBT_GLOBAL_SP_ECDH_SHARE, PSBT_GLOBAL_SP_DLEQ, PSBT_GLOBAL_TX_MODIFIABLE}
SP_INPUT_TYPES = {PSBT_IN_SP_ECDH_SHARE, PSBT_IN_SP_DLEQ}
SP_OUTPUT_TYPES = {PSBT_OUT_SP_V0_INFO, PSBT_OUT_SP_V0_LABEL, PSBT_OUT_SCRIPT}


def run_vector(vector: dict) -> list[str]:
    task = vector.get("task")
    expected = vector.get("expected") or {}
    if task == "create":
        return _create(vector, expected)
    if not vector.get("psbt"):
        return ["missing incoming psbt"]
    incoming = BIP375PSBT.from_base64(vector["psbt"])
    failures = _parsed_checks(incoming, "incoming")
    if task == "deserialize":
        return failures
    if task == "update":
        return failures + _update(incoming, expected)
    if task == "sign":
        return failures + _sign(incoming, vector, expected)
    if task == "finalize":
        return failures + _finalize(incoming, expected)
    if task == "extract":
        return failures + _extract(incoming, expected)
    return failures + [f"unknown task '{task}'"]


def run_vectors(vectors: list, verbose: bool = False) -> tuple[int, int]:
    passed = failed = 0
    for vector in vectors:
        print(vector["description"])
        try:
            failures = run_vector(vector)
        except Exception as exc:
            failures = [f"{type(exc).__name__}: {exc}"]
            if verbose:
                traceback.print_exc()
        if failures:
            failed += 1
            print(f"  {vector.get('task')}: FAILED")
            for failure in failures:
                print(f"    {failure}")
        else:
            passed += 1
            if verbose:
                print(f"  {vector.get('task')}: PASSED")
    return passed, failed


def _checks(b64: str | None, label: str) -> list[str]:
    if not b64:
        return [f"{label} psbt is missing"]
    try:
        psbt = BIP375PSBT.from_base64(b64)
    except Exception as exc:
        return [f"{label} psbt does not parse: {exc}"]
    return _parsed_checks(psbt, label)


def _parsed_checks(psbt: BIP375PSBT, label: str) -> list[str]:
    ok, msg, check = run_checks(psbt)
    if ok:
        return []
    return [f"{label} fails {check}: {msg}"]


def _acting_keys(vector: dict) -> list[tuple[int, bytes]]:
    keys = []
    for item in vector.get("supplementary", {}).get("inputs") or []:
        raw = item.get("private_key")
        if raw:
            keys.append((item["input_index"], bytes.fromhex(raw)))
    return keys


def _aux_rand(vector: dict) -> dict[tuple[bytes, int | None], bytes]:
    found = {}
    for item in vector.get("supplementary", {}).get("dleq_aux_rand") or []:
        scan = bytes.fromhex(item["scan_key"])
        index = item.get("input_index")
        found[(scan, index)] = bytes.fromhex(item["aux_rand"])
    return found

# ============================================================================
# Role specific handlers for each task in the workflow
# ============================================================================


def _create(vector: dict, expected: dict) -> list[str]:
    """Check expected.psbt against the inputs and outputs in supplementary.
    Outpoints and SP_V0_INFO feed the output scripts, so a mismatch fails.
    Amounts and sequences do not, so a mismatch passes with a warning."""
    if "psbt" not in expected:
        return ["create vector has no expected.psbt"]
    expected_psbt = BIP375PSBT.from_base64(expected["psbt"])
    inputs = vector.get("supplementary", {}).get("inputs") or []
    outputs = vector.get("supplementary", {}).get("outputs") or []
    if len(inputs) != len(expected_psbt.i) or len(outputs) != len(expected_psbt.o):
        return ["created PSBT has a different number of inputs or outputs than supplementary"]
    failures = []
    for item in inputs:
        index = item["input_index"]
        inp = expected_psbt.i[index]
        txid = bytes.fromhex(item["prevout_txid"])[::-1]
        vout = struct.pack("<I", item["prevout_index"])
        if inp.get(PSBT_IN_PREVIOUS_TXID) != txid or inp.get(PSBT_IN_OUTPUT_INDEX) != vout:
            failures.append(f"input[{index}] outpoint does not match supplementary")
        sequence = inp.get(PSBT_IN_SEQUENCE, struct.pack("<I", 0xFFFFFFFF))
        if "sequence" in item and sequence != struct.pack("<I", item["sequence"]):
            print(f"  WARNING: input[{index}] sequence does not match supplementary")
        failures += _early_sp_fields(inp.map, f"input[{index}]", SP_INPUT_TYPES)
    for item in outputs:
        index = item["output_index"]
        out = expected_psbt.o[index]
        if "sp_v0_info" in item:
            if out.get(PSBT_OUT_SP_V0_INFO) != bytes.fromhex(item["sp_v0_info"]):
                failures.append(f"output[{index}] SP_V0_INFO does not match supplementary")
            if PSBT_OUT_SCRIPT in out:
                failures.append(f"output[{index}] has PSBT_OUT_SCRIPT before any share is computed")
        if out.get(PSBT_OUT_AMOUNT) != struct.pack("<q", item["amount"]):
            print(f"  WARNING: output[{index}] amount does not match supplementary")
    sp_globals = {PSBT_GLOBAL_SP_ECDH_SHARE, PSBT_GLOBAL_SP_DLEQ}
    failures += _early_sp_fields(expected_psbt.g.map, "global", sp_globals)
    return failures + _parsed_checks(expected_psbt, "expected")


def _early_sp_fields(psbt_map: dict, label: str, types: set[int]) -> list[str]:
    """A Creator cannot have computed ECDH shares or DLEQ proofs yet"""
    found = sorted({_type_of(key) for key in psbt_map if _type_of(key) in types})
    return [f"{label} has field {key_type:#x} before any share is computed" for key_type in found]


def _update(incoming: BIP375PSBT, expected: dict) -> list[str]:
    if "psbt" not in expected:
        return ["update vector has no expected.psbt"]
    expected_psbt = BIP375PSBT.from_base64(expected["psbt"])
    if len(incoming.o) != len(expected_psbt.o) or len(incoming.i) != len(expected_psbt.i):
        return ["updated PSBT changed the number of inputs or outputs"]
    # A change to a silent payment field fails. Any other change beyond adding
    # input fields passes with a warning: the generator owns PSBT compliance.
    failures = _diff_selected(incoming.g.map, expected_psbt.g.map, "global", SP_GLOBAL_TYPES)
    if _other_diffs(incoming.g.map, expected_psbt.g.map, SP_GLOBAL_TYPES):
        print("  WARNING: global map changed during update")
    for index, (got, exp) in enumerate(zip(incoming.o, expected_psbt.o)):
        failures += _diff_selected(got.map, exp.map, f"output[{index}]", SP_OUTPUT_TYPES)
        if _other_diffs(got.map, exp.map, SP_OUTPUT_TYPES):
            print(f"  WARNING: output[{index}] changed during update")
    # Once the Updater is done, a Signer must be able to tell whether each
    # input is eligible.
    for index, (got, exp) in enumerate(zip(incoming.i, expected_psbt.i)):
        failures += _diff_selected(got.map, exp.map, f"input[{index}]", SP_INPUT_TYPES)
        if any(exp.map.get(key) != value for key, value in got.map.items()):
            print(f"  WARNING: input[{index}] field removed or changed during update")
        try:
            is_input_eligible(exp, index)
        except ValidationError as exc:
            failures.append(f"input[{index}] eligibility undetermined after update: {exc}")
    return failures + _parsed_checks(expected_psbt, "expected")


def _sign(incoming: BIP375PSBT, vector: dict, expected: dict) -> list[str]:
    if "psbt" not in expected:
        return ["sign vector has no expected.psbt"]
    expected_psbt = BIP375PSBT.from_base64(expected["psbt"])
    got = sign_sp_psbt(incoming, _acting_keys(vector), _aux_rand(vector))
    failures = _sp_field_diffs(got, expected_psbt)
    return failures + _parsed_checks(expected_psbt, "expected")


def _finalize(incoming: BIP375PSBT, expected: dict) -> list[str]:
    if "psbt" not in expected:
        return ["finalize vector has no expected.psbt"]
    expected_psbt = BIP375PSBT.from_base64(expected["psbt"])
    failures = []
    if len(incoming.o) != len(expected_psbt.o) or len(incoming.i) != len(expected_psbt.i):
        failures.append("finalized PSBT changed the number of inputs or outputs")
    for index, (got, exp) in enumerate(zip(incoming.o, expected_psbt.o)):
        if got.map != exp.map:
            failures.append(f"output[{index}] changed during finalize")
    for index, (got, exp) in enumerate(zip(incoming.i, expected_psbt.i)):
        if got.get(PSBT_IN_PREVIOUS_TXID) != exp.get(PSBT_IN_PREVIOUS_TXID) or got.get(PSBT_IN_OUTPUT_INDEX) != exp.get(PSBT_IN_OUTPUT_INDEX):
            failures.append(f"input[{index}] outpoint changed during finalize")
    return failures + _parsed_checks(expected_psbt, "expected")


def _extract(incoming: BIP375PSBT, expected: dict) -> list[str]:
    raw = expected.get("tx")
    if not raw:
        return ["extract vector has no expected.tx"]
    tx = CTransaction()
    tx.deserialize(BytesIO(bytes.fromhex(raw)))
    failures = []
    if len(tx.vout) != len(incoming.o) or len(tx.vin) != len(incoming.i):
        return ["expected.tx has a different number of inputs or outputs"]
    for index, (txout, output) in enumerate(zip(tx.vout, incoming.o)):
        if PSBT_OUT_SP_V0_INFO not in output:
            continue
        if bytes(txout.scriptPubKey) != output.get(PSBT_OUT_SCRIPT, b""):
            failures.append(f"output[{index}] script of expected.tx does not match the verified PSBT_OUT_SCRIPT")
    for index, (txin, inp) in enumerate(zip(tx.vin, incoming.i)):
        txid = int.from_bytes(inp[PSBT_IN_PREVIOUS_TXID], "little")
        vout = struct.unpack("<I", inp[PSBT_IN_OUTPUT_INDEX])[0]
        if txin.prevout.hash != txid or txin.prevout.n != vout:
            failures.append(f"input[{index}] outpoint of expected.tx does not match the PSBT")
    return failures


def _type_of(key) -> int:
    return key if isinstance(key, int) else key[0]

# ============================================================================
# PSBT field comparison helpers
# ============================================================================

def _sp_field_diffs(got: BIP375PSBT, expected: BIP375PSBT) -> list[str]:
    failures = []
    failures += _diff_selected(got.g.map, expected.g.map, "global", SP_GLOBAL_TYPES)
    for index, (got_in, exp_in) in enumerate(zip(got.i, expected.i)):
        failures += _diff_selected(got_in.map, exp_in.map, f"input[{index}]", SP_INPUT_TYPES)
    for index, (got_out, exp_out) in enumerate(zip(got.o, expected.o)):
        if PSBT_OUT_SP_V0_INFO not in exp_out and PSBT_OUT_SP_V0_INFO not in got_out:
            continue
        if got_out.get(PSBT_OUT_SCRIPT) != exp_out.get(PSBT_OUT_SCRIPT):
            failures.append(f"output[{index}] PSBT_OUT_SCRIPT does not match expected")
    return failures


def _other_diffs(got: dict, expected: dict, types: set[int]) -> bool:
    """True if the maps differ in any field whose type is not in types"""
    keys = {key for key in set(got) | set(expected) if _type_of(key) not in types}
    return any(got.get(key) != expected.get(key) for key in keys)


def _diff_selected(got: dict, expected: dict, label: str, types: set[int]) -> list[str]:
    failures = []
    keys = {key for key in set(got) | set(expected) if _type_of(key) in types}
    for key in keys:
        if got.get(key) != expected.get(key):
            failures.append(f"{label} field {_type_of(key):#x} does not match expected")
    return failures
