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

from validator.validate_psbt import validate_bip375_psbt
from workflow.validate_workflow import run_vectors


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

    The `task` tag pins which check must be the one that rejects it:
    `fail_deserialize` must be rejected by the structural check, while
    `fail_sign` must pass structure and only fail a later check.
    """
    passed = 0
    failed = 0

    invalid_tests = test_data.get("invalid", [])
    print(f"Invalid PSBTs: {len(invalid_tests)}")
    for test_vector in invalid_tests:
        is_valid, result, failing_check = validate_bip375_psbt(
            test_vector["psbt"], test_vector.get("checks"), debug=verbosity >= 2
        )
        task = test_vector.get("supplementary", {}).get("task")

        print(f"{test_vector['description']}")
        if is_valid:
            failed += 1
            print("  ERROR: expected validation to fail")
            continue
        if task == "fail_deserialize" and failing_check != "psbt_structure":
            failed += 1
            print(
                f"  ERROR: task 'fail_deserialize' expects the psbt_structure check "
                f"to fail, but '{failing_check}' failed instead"
            )
            continue
        if task == "fail_sign" and failing_check == "psbt_structure":
            failed += 1
            print(
                "  ERROR: task 'fail_sign' expects a later check to fail, but "
                "psbt_structure failed"
            )
            continue

        passed += 1
        if verbosity >= 1:
            print(f"  {failing_check}: {result}")

    return passed, failed


def run_valid_tests(test_data: dict, verbosity: int = 0) -> tuple[int, int]:
    """Run the `valid` section: validate the incoming PSBT, then drive the role
    its task names and match the result to expected.psbt."""
    valid_tests = test_data.get("valid", [])
    print(f"Valid PSBTs: {len(valid_tests)}")
    return run_vectors(valid_tests, verbose=verbosity >= 1)


def run_workflow_tests(test_data: dict, verbosity: int = 0) -> tuple[int, int]:
    """Run the `workflows` section: each entry is one role transition."""
    steps = test_data.get("workflows", [])
    print(f"Workflow steps: {len(steps)}")
    return run_vectors(steps, verbose=verbosity >= 1)


SECTIONS = {
    "invalid": run_invalid_tests,
    "valid": run_valid_tests,
    "workflow": run_workflow_tests,
}


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
    parser.add_argument(
        "--section",
        "-s",
        action="append",
        choices=SECTIONS,
        help="Run only this section (repeatable; default: every section)",
    )

    args = parser.parse_args()

    test_data = load_test_vectors(args.test_file)

    print(f"Description: {test_data.get('description', 'N/A')}")
    print(f"Version: {test_data.get('version', 'N/A')}")
    print()

    passed = failed = 0
    for name, run_section in SECTIONS.items():
        if args.section and name not in args.section:
            continue
        section_passed, section_failed = run_section(test_data, args.verbosity)
        passed += section_passed
        failed += section_failed
        print()

    print(f"Summary: {passed} passed, {failed} failed")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
