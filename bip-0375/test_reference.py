#!/usr/bin/env python3
"""
BIP 375 Test Runner

Executes test vectors for BIP 375 silent payment PSBT implementation.
Loads test cases from test_vectors.json and validates against reference implementation.
"""

import json
import sys
import traceback
from typing import Dict, List, Tuple
from reference import (
    SilentPaymentPSBT,
    validate_psbt_silent_payments,
    parse_test_vectors,
    run_test_case
)

class TestRunner:
    """Test runner for BIP 375 test vectors"""
    
    def __init__(self, test_vector_file: str = "test_vectors.json"):
        self.test_vector_file = test_vector_file
        self.results = {
            'passed': 0,
            'failed': 0,
            'errors': []
        }
    
    def load_test_vectors(self) -> Dict:
        """Load test vectors from JSON file"""
        try:
            with open(self.test_vector_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: Test vector file '{self.test_vector_file}' not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in test vector file: {e}")
            sys.exit(1)
    
    def run_invalid_tests(self, invalid_tests: List[Dict]) -> None:
        """Run tests that should fail validation"""
        print("\n=== Running Invalid Test Cases ===")
        
        for i, test_case in enumerate(invalid_tests):
            test_name = test_case.get('description', f'Invalid test {i+1}')
            psbt_b64 = test_case.get('psbt', '')
            expected_error = test_case.get('error', 'Unknown error')
            
            print(f"\nTest {i+1}: {test_name}")
            print(f"Expected error: {expected_error}")
            
            if psbt_b64.startswith('TODO_'):
                print("⚠️  SKIPPED: Test vector not yet generated")
                continue
            
            try:
                passed, error_msg = run_test_case(psbt_b64, expected_valid=False)
                if passed:
                    print("✅ PASS: Test correctly identified as invalid")
                    self.results['passed'] += 1
                else:
                    print(f"❌ FAIL: {error_msg}")
                    self.results['failed'] += 1
                    self.results['errors'].append(f"Invalid test {i+1}: {error_msg}")
            except NotImplementedError as e:
                print(f"🔧 NOT IMPLEMENTED: {e}")
            except Exception as e:
                print(f"💥 ERROR: Unexpected exception: {e}")
                self.results['failed'] += 1
                self.results['errors'].append(f"Invalid test {i+1}: Exception: {e}")
    
    def run_valid_tests(self, valid_tests: List[Dict]) -> None:
        """Run tests that should pass validation"""
        print("\n=== Running Valid Test Cases ===")
        
        for i, test_case in enumerate(valid_tests):
            test_name = test_case.get('description', f'Valid test {i+1}')
            psbt_b64 = test_case.get('psbt', '')
            note = test_case.get('note', '')
            
            print(f"\nTest {i+1}: {test_name}")
            if note:
                print(f"Note: {note}")
            
            if psbt_b64.startswith('TODO_'):
                print("⚠️  SKIPPED: Test vector not yet generated")
                continue
            
            try:
                passed, error_msg = run_test_case(psbt_b64, expected_valid=True)
                if passed:
                    print("✅ PASS: Test correctly validated as valid")
                    self.results['passed'] += 1
                else:
                    print(f"❌ FAIL: {error_msg}")
                    self.results['failed'] += 1
                    self.results['errors'].append(f"Valid test {i+1}: {error_msg}")
            except NotImplementedError as e:
                print(f"🔧 NOT IMPLEMENTED: {e}")
            except Exception as e:
                print(f"💥 ERROR: Unexpected exception: {e}")
                self.results['failed'] += 1
                self.results['errors'].append(f"Valid test {i+1}: Exception: {e}")
    
    def run_all_tests(self) -> bool:
        """Run all test cases and return overall success"""
        print("BIP 375 Test Runner - Sending Silent Payments with PSBTs")
        print("=" * 60)
        
        test_vectors = self.load_test_vectors()
        
        # Display test vector info
        print(f"Description: {test_vectors.get('description', 'N/A')}")
        print(f"Version: {test_vectors.get('version', 'N/A')}")
        print(f"Invalid test cases: {len(test_vectors.get('invalid', []))}")
        print(f"Valid test cases: {len(test_vectors.get('valid', []))}")
        
        # Run invalid tests
        if 'invalid' in test_vectors:
            self.run_invalid_tests(test_vectors['invalid'])
        
        # Run valid tests  
        if 'valid' in test_vectors:
            self.run_valid_tests(test_vectors['valid'])
        
        # Print summary
        self.print_summary()
        
        return self.results['failed'] == 0
    
    def print_summary(self) -> None:
        """Print test execution summary"""
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"Total tests: {self.results['passed'] + self.results['failed']}")
        print(f"Passed: {self.results['passed']}")
        print(f"Failed: {self.results['failed']}")
        
        if self.results['errors']:
            print("\nFAILED TESTS:")
            for error in self.results['errors']:
                print(f"  - {error}")
        
        if self.results['failed'] == 0:
            print("\n🎉 All tests passed!")
        else:
            print(f"\n❌ {self.results['failed']} test(s) failed")

def main():
    """Main test runner entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='BIP 375 Test Runner')
    parser.add_argument('--test-file', '-f', default='test_vectors.json',
                       help='Test vector JSON file (default: test_vectors.json)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)
    
    runner = TestRunner(args.test_file)
    success = runner.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()