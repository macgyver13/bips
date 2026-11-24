#!/usr/bin/env python3
"""Process test vectors JSON file and run validation checks"""

import argparse
import json
from pathlib import Path
import sys

project_root = Path(__file__).parent
deps_dir = project_root / "deps"
secp256k1lab_dir = deps_dir / "secp256k1lab" / "src"
for path in [str(deps_dir), str(secp256k1lab_dir)]:
    if path not in sys.path:
        sys.path.insert(0, path)

from validator.psbt_bip375 import BIP375PSBT, ValidationError
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


def validate_bip375_psbt(psbt_data: str) -> tuple[bool, str, str | None]:
    """Performs sequential validation of a PSBT against BIP-375 rules.

    Returns (is_valid, message, failing_check): failing_check names the check
    that rejected the PSBT, or None if every check passed. A PSBT that does
    not parse counts as a PSBT Structure failure.
    """
    try:
        psbt = BIP375PSBT.from_base64(psbt_data)
    except ValueError as e:
        return False, str(e), "psbt_structure"

    for check_name, check_fn in CHECK_FUNCTIONS.items():
        try:
            check_fn(psbt)
        except ValidationError as e:
            return False, str(e), check_name

    return True, "All checks passed", None


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


def run_invalid_tests(test_data: dict, verbosity: int = 0) -> tuple[int, int, int]:
    """Run the `invalid` section (each PSBT should fail validation).

    The `task` defines which check must reject it:
    `fail_deserialize` must be rejected by the structural check, while
    `fail_sign` must pass structure and only fail a later check.
    """
    passed = 0
    failed = 0
    skipped = 0

    invalid_tests = test_data.get("invalid", [])
    print(f"Invalid PSBTs: {len(invalid_tests)}")
    for test_vector in invalid_tests:
        task = test_vector.get("task")

        print(f"{test_vector['description']}")
        if task not in ("fail_deserialize", "fail_sign"):
            skipped += 1
            print(f"  SKIPPED: task '{task}'")
            continue
        is_valid, result, failing_check = validate_bip375_psbt(test_vector["psbt"])
        if is_valid:
            failed += 1
            print("  ERROR: expected validation to fail")
            continue
        if (failing_check == "psbt_structure") != (task == "fail_deserialize"):
            failed += 1
            print(f"  ERROR: task '{task}' but rejected by {failing_check}: {result}")
            continue

        passed += 1
        if verbosity >= 2:
            print(f"  {failing_check.upper()}: {result}")
        elif verbosity >= 1:
            print(f"  {result}")

    return passed, failed, skipped


def run_valid_tests(test_data: dict, verbosity: int = 0) -> tuple[int, int]:
    """Run the `valid` section (each PSBT should pass validation)."""
    passed = 0
    failed = 0

    valid_tests = test_data.get("valid", [])
    print(f"Valid PSBTs: {len(valid_tests)}")
    for test_vector in valid_tests:
        print(f"{test_vector['description']}")

        is_valid, result, failing_check = validate_bip375_psbt(test_vector["psbt"])
        if is_valid:
            passed += 1
            if verbosity >= 1:
                print(f"  {result}")
        else:
            failed += 1
            if verbosity >= 2:
                result = f"{failing_check.upper()}: {result}"
            print(f"  ERROR: {result}")

    return passed, failed


def run_validation_tests(test_data: dict, verbosity: int = 0) -> tuple[int, int, int]:
    """Run validation checks for both sections."""
    invalid_passed, invalid_failed, skipped = run_invalid_tests(test_data, verbosity)
    print("")
    valid_passed, valid_failed = run_valid_tests(test_data, verbosity)
    return invalid_passed + valid_passed, invalid_failed + valid_failed, skipped


def main():
    parser = argparse.ArgumentParser(
        description="Silent Payments PSBT Validator",
    )
    parser.add_argument(
        "--test-file",
        "-f",
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

    args = parser.parse_args()

    test_data = load_test_vectors(args.test_file)

    print(f"Description: {test_data.get('description', 'N/A')}")
    print(f"Version: {test_data.get('version', 'N/A')}")
    print()

    passed, failed, skipped = run_validation_tests(test_data, args.verbosity)

    print()
    print(f"Summary: {passed} passed, {failed} failed, {skipped} skipped")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
