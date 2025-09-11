#!/usr/bin/env python3
"""
Complete BIP 375 Test Runner

Test runner for complete BIP 375 test vectors with full PSBT structures
that properly trigger validation rules. Tests all scenarios from test_vectors.json.
"""

import json
import argparse
import sys
from typing import Dict
from reference import run_test_case

def load_test_vectors(filename: str) -> Dict:
    """Load test vectors from JSON file"""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Test vector file '{filename}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in test vector file: {e}")
        sys.exit(1)

def parse_test(test_vector: Dict) -> tuple:
    """Parse test vector"""
    psbt_b64 = test_vector['psbt']
    input_keys = test_vector.get('input_keys', [])
    expected_ecdh_shares = test_vector.get('expected_ecdh_shares', [])
    
    return psbt_b64, input_keys, expected_ecdh_shares

def run_tests(test_data: Dict, verbose: bool = False) -> tuple[int, int]:
    """Run all complete test cases and return (passed, total)"""
    
    print("Complete BIP 375 Test Runner - All Scenarios")
    print("=" * 50)
    print(f"Description: {test_data['description']}")
    print(f"Version: {test_data['version']}")
    print(f"Invalid test cases: {len(test_data['invalid'])}")
    print(f"Valid test cases: {len(test_data['valid'])}")
    
    test_num = 1

    # Run invalid test cases
    print(f"\n=== Running Invalid Test Cases ===")
    for test_case in test_data['invalid']:
        
        description = test_case['description']
        expected_error = test_case.get('comment', 'unknown error')
        
        print(f"Test {test_num}: {description}")
        
        
        psbt_b64, input_keys, expected_ecdh_shares = parse_test(test_case)
        
        # Run the enhanced test case
        is_valid, error_msg = run_test_case(
            psbt_b64=psbt_b64,
            input_keys=input_keys,
            expected_ecdh_shares=expected_ecdh_shares
        )
        
        assert not is_valid, error_msg
        if verbose:
            print(f"     Comment: {expected_error}")
            print(f"     Details: {error_msg}")
        test_num += 1

    # Run valid test cases
    print()
    print(f"=== Running Valid Test Cases ===")
    for test_case in test_data['valid']:
        description = test_case['description']
        
        print(f"Test {test_num}: {description}")
        if verbose:
            print(f"     Comment: {test_case.get('comment', '')}")
        
        # try:
        psbt_b64, input_keys, expected_ecdh_shares = parse_test(test_case)
        
        # Run the enhanced test case  
        is_valid, error_msg = run_test_case(
            psbt_b64=psbt_b64,
            input_keys=input_keys,
            expected_ecdh_shares=expected_ecdh_shares
        )
        
        assert is_valid, error_msg
        test_num += 1


def main():
    parser = argparse.ArgumentParser(description='Complete BIP 375 Test Runner')
    parser.add_argument('--test-file', '-f', default='test_vectors.json',
                      help='Test vector file to run (default: test_vectors.json)')
    parser.add_argument('--verbose', '-v', action='store_true',
                      help='Show detailed error messages and exception details')
    
    args = parser.parse_args()
    
    # Load test vectors
    test_data = load_test_vectors(args.test_file)
    
    # Run tests
    run_tests(test_data, args.verbose)

if __name__ == "__main__":
    main()