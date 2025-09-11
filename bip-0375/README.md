# BIP 375 Reference Implementation

This directory contains the complete reference implementation for BIP 375: Sending Silent Payments with PSBTs.

## 🎯 **Core Files** 

### Main Implementation
- **`reference.py`** - Complete BIP 375 reference implementation with PSBT v2 parsing, validation, and enhanced DLEQ verification

### Dependencies (from BIP 374)
- **`dleq_374.py`** - BIP 374 DLEQ proof implementation (copied from official BIP 374 reference)
- **`secp256k1_374.py`** - Secp256k1 implementation (copied from official BIP 374 reference)

### Utilities
- **`psbt_utils.py`** - PSBT v2 utilities for serialization and parsing

## 🧪 **Testing**

### Test Vectors
- **`test_vectors.json`** - Test vectors with full cryptographic material (3 invalid + 2 valid scenarios)

### Test Infrastructure
- **`test_generator.py`** - Deterministic test vector generator with real PSBT structures
- **`test_runner.py`** - Test runner with full BIP 375 validation and enhanced DLEQ verification

## 🏗️ **Supporting Directories**

- **`design_material/`** - Original design documents and planning materials
- **`examples/`** - Example scripts demonstrating different BIP 375 scenarios
- **`diagnostics/`** - Development artifacts and debug files (not needed for production)

## 🚀 **Usage**

### Run All Tests
```bash
python test_runner.py
```

### Generate New Test Vectors
```bash
python test_generator.py
```

## ✅ **Test Results**

**5/5 tests passing (100% success rate)**

- ✅ Missing DLEQ proof for ECDH share
- ✅ Invalid DLEQ proof  
- ✅ Non-SIGHASH_ALL signature with silent payments
- ✅ Single signer with global ECDH share
- ✅ Multi-party with per-input ECDH shares

## 🔐 **Security Features**

- **Complete BIP 375 validation** - All PSBT rules enforced
- **Full BIP 374 DLEQ verification** - Cryptographic proof validation using official reference
- **Multi-party support** - Both global and per-input ECDH share workflows
- **Deterministic testing** - Reproducible test vectors with known cryptographic material

This implementation provides production-ready BIP 375 functionality suitable for Bitcoin wallet integration.