#!/usr/bin/env python3
"""Process test vectors JSON file and run validation checks"""

import argparse
import json
from pathlib import Path
import sys
from typing import Tuple

project_root = Path(__file__).parent
deps_dir = project_root / "deps"
secp256k1lab_dir = deps_dir / "secp256k1lab" / "src"
for path in [str(deps_dir), str(secp256k1lab_dir)]:
    if path not in sys.path:
        sys.path.insert(0, path)

from validator.psbt_bip375 import BIP375PSBT
from validator.validate_psbt import (
    validate_psbt_structure,
    validate_ecdh_coverage,
    validate_input_eligibility,
    validate_output_scripts,
)

CHECK_FUNCTIONS = {
    "psbt_structure": validate_psbt_structure,
    "ecdh_coverage": validate_ecdh_coverage,
    "input_eligibility": validate_input_eligibility,
    "output_scripts": validate_output_scripts,
}


def validate_bip375_psbt(
    psbt_data: str, checks: list[str], debug: bool = False
) -> Tuple[bool, str]:
    """Performs sequential validation of a PSBT against BIP-375 rules"""
    psbt = BIP375PSBT.from_base64(psbt_data)

    if checks is None:
        checks = [
            "psbt_structure",
            "ecdh_coverage",
            "input_eligibility",
            "output_scripts",
        ]

    for check_name in checks:
        if check_name not in CHECK_FUNCTIONS:
            return False, f"Unknown check: {check_name}"

        check_fn = CHECK_FUNCTIONS[check_name]

        is_valid, msg = check_fn(psbt)
        if debug:
            msg = f"{check_name.upper()}: {msg}" if msg else msg

        if not is_valid:
            return False, msg

    return True, "All checks passed"


def load_test_vectors(filename: str) -> dict:
    """Load test vectors from JSON file"""
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Test vector file '{filename}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in test vector file: {e}")
        sys.exit(1)


def run_invalid_tests(test_data: dict, verbosity: int = 0) -> tuple[int, int]:
    """Run the `invalid` section (each PSBT should fail validation).

    The `task` tag pins the highest pipeline step that should still pass:
    `fail_deserialize` must be rejected at the structural gate, while `fail_sign`
    must deserialize into a structurally valid PSBT and only fail a later,
    signing-stage check.
    """
    passed = 0
    failed = 0

    invalid_tests = test_data.get("invalid", [])
    print(f"Invalid PSBTs: {len(invalid_tests)}")
    for test_vector in invalid_tests:
        is_valid, result = validate_bip375_psbt(
            test_vector["psbt"], test_vector.get("checks"), debug=verbosity >= 2
        )
        task = test_vector.get("supplementary", {}).get("task")
        struct_ok, _ = validate_psbt_structure(BIP375PSBT.from_base64(test_vector["psbt"]))

        # Task-based gate: fail_deserialize fails structure; fail_sign passes it.
        if task == "fail_deserialize":
            gate_ok = not struct_ok
        elif task == "fail_sign":
            gate_ok = struct_ok
        else:
            gate_ok = True

        print(f"{test_vector['description']}")
        if not is_valid and gate_ok:
            passed += 1
            if verbosity >= 1:
                print(f"  {result}")
        else:
            failed += 1
            if is_valid and result:
                print(f"  ERROR: {result}")
            if not gate_ok:
                print(f"  ERROR: task '{task}' expects structure check to "
                      f"{'fail' if task == 'fail_deserialize' else 'pass'}, but it "
                      f"{'passed' if struct_ok else 'failed'}")

    return passed, failed


def run_valid_tests(test_data: dict, verbosity: int = 0) -> tuple[int, int]:
    """Run the `valid` section stepwise: validate the incoming PSBT, then drive
    the role named by supplementary.task and match the result to expected.psbt."""
    # Imported here to keep the module-level import direction one-way:
    # workflow.validate_workflow imports validate_bip375_psbt from this module.
    from workflow.validate_workflow import run_valid_stepwise

    return run_valid_stepwise(test_data.get("valid", []), verbose=verbosity >= 1)


def main():
    parser = argparse.ArgumentParser(
        description="Silent Payments PSBT Validator",
    )
    parser.add_argument(
        "-f",
        "--test-file",
        default=str(project_root / "bip375_test_vectors.json"),
        help="Test vector file to run (default: bip375_test_vectors.json)",
    )
    parser.add_argument(
        "-v",
        dest="verbosity",
        action="count",
        default=0,
        help="Verbosity level: -v shows pass/fail details, -vv enables debug output",
    )
    parser.add_argument(
        "-va",
        "--valid",
        action="store_true",
        help="Run the valid PSBT section",
    )
    parser.add_argument(
        "-i",
        "--invalid",
        action="store_true",
        help="Run the invalid PSBT section",
    )
    parser.add_argument(
        "-w",
        "--workflow",
        action="store_true",
        help="Run the role-based workflow section",
    )

    args = parser.parse_args()

    # No section flag selects everything.
    run_all = not (args.valid or args.invalid or args.workflow)

    test_data = load_test_vectors(args.test_file)

    print(f"Description: {test_data.get('description', 'N/A')}")
    print(f"Version: {test_data.get('version', 'N/A')}")
    print()

    passed = 0
    failed = 0

    if run_all or args.invalid:
        p, f = run_invalid_tests(test_data, args.verbosity)
        passed += p
        failed += f
        print()

    if run_all or args.valid:
        p, f = run_valid_tests(test_data, args.verbosity)
        passed += p
        failed += f
        print()

    if run_all or args.workflow:
        # Imported here to keep the module-level import direction one-way:
        # workflow.validate_workflow imports validate_bip375_psbt from this module.
        from workflow.validate_workflow import run_workflow_validation

        print("=== Workflow Tests ===")
        p, f = run_workflow_validation(test_data, verbose=args.verbosity >= 1)
        passed += p
        failed += f
        print()

    print(f"Summary: {passed} passed, {failed} failed")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
