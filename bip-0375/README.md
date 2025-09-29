# BIP 375 Reference Implementation

This directory contains the complete reference implementation for BIP 375: Sending Silent Payments with PSBTs.

## **Core Files**

### Reference Implementation

- **`reference.py`** - Minimal standalone BIP 375 validator with integrated test runner (executable)

### Production Library

- **`psbt_sp/`** - Complete PSBT v2 package for Silent Payments
  - Full role-based implementation (Creator, Constructor, Updater, Signer, Input Finalizer, Extractor)
  - Serialization, crypto utilities, and BIP 352 integration
  - See psbt_sp package for production use

### Dependencies (from BIP 374)

- **`dleq_374.py`** - BIP 374 DLEQ proof implementation
- **`secp256k1_374.py`** - Secp256k1 implementation

## **Testing**

### Test Infrastructure

- **`test_vectors.json`** - Test vectors with full cryptographic material (7 invalid + 4 valid)
- **`tests/test_generator.py`** - Deterministic test vector generator producing `test_vectors.json`
- **`tests/test_vector_validator.py`** - Advanced validator using psbt_sp package (4-stage validation)
- **`tests/validate_tests_examples.py`** - Validate test_vector_validator, reference, and examples

## **Examples**

- **`examples/`** - Production-ready examples demonstrating BIP 375 workflows
  - [Hardware Signer](examples/hardware_signer/README.md) - Hardware wallet integration
  - [Multi Party Signer](examples/multi_signer/README.md) - Collaborative signing workflow

## **Usage**

### Run Reference Implementation Tests

```bash
python reference.py                    # Run all tests using test_vectors.json
python reference.py -f custom.json     # Use custom test file
python reference.py -v                 # Verbose mode with detailed errors
```

### Generate Test Vectors

```bash
python tests/test_generator.py               # Creates test_vectors.json in root directory
```

### Advanced Validation (psbt_sp package)

```bash
python tests/test_vector_validator.py -v    # 4-stage validation with verbose output
```

**Note:** Both test tools automatically look for `test_vectors.json` in the bip-0375 root directory.

