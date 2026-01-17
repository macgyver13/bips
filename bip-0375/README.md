# BIP 375 Reference Implementation

This directory contains reference implementation for BIP 375: Sending Silent Payments with PSBTs.

## Core Files
- **`constants.py`** - PSBT field type definitions
- **`parser.py`** - PSBT structure parsing
- **`inputs.py`** - Input validation helpers
- **`dleq.py`** - DLEQ proof validation
- **`validator.py`** - Main BIP 375 validator
- **`test_runner.py`** - Test infrastructure (executable)

## Dependencies
- **`../bip-0374/reference.py`** - BIP 374 DLEQ proof verification functions
- **`bip-0375/secp256k1lab/`** - Vendored secp256k1 reference implementation
  - Version: 1.0.0 (commit [44dc4bd](https://github.com/secp256k1lab/secp256k1lab/commit/44dc4bd893b8f03e621585e3bf255253e0e0fbfb))
  - Source: [secp256k1lab/secp256k1lab](https://github.com/secp256k1lab/secp256k1lab/)

## Testing

### Test Vectors
- **`test_vectors.json`** - 18 test vectors (12 invalid + 6 valid) covering:
```bash
jq '.invalid[].description, .valid[].description' test_vectors.json

"Detect missing PSBT_IN_SP_DLEQ proof field for PSBT_IN_SP_ECDH_SHARE"
"Detect invalid DLEQ proof in PSBT_IN_SP_DLEQ field"
"Reject PSBT with non-SIGHASH_ALL signatures and PSBT_OUT_SP_V0_INFO field set"
"Detect segwit version greater than 1 in transaction inputs with PSBT_OUT_SP_V0_INFO field set"
"Detect missing PSBT_IN_SP_ECDH_SHARE with silent payment outputs defined"
"Detect missing PSBT_GLOBAL_SP_DLEQ proof field matching PSBT_GLOBAL_SP_ECDH_SHARE"
"Detect PSBT_OUT_SP_V0_INFO field with incorrect size"
"Detect PSBT_IN_SP_ECDH_SHARE field with incorrect size"
"Detect PSBT_IN_SP_DLEQ proof field with incorrect size"
"Detect PSBT_OUT_SP_V0_LABEL field present without required PSBT_OUT_SP_V0_INFO field"
"Detect computed output script mismatch in PSBT_OUT_SCRIPT field from transaction inputs and PSBT_IN_SP_ECDH_SHARE field"
"Reject PSBT with PSBT_GLOBAL_SP_ECDH_SHARE and PSBT_IN_SP_ECDH_SHARE fields present for the same scan key"

"Valid PSBT where a single entity controls all inputs and uses the global ECDH share approach (PSBT_GLOBAL_SP_ECDH_SHARE) for efficiency"
"Valid PSBT with multiple parties (two signers) where each signer contributes per-input ECDH shares (PSBT_IN_SP_ECDH_SHARE) for their respective inputs"
"Valid PSBT sending from P2WPKH to silent payment address with change output, using PSBT_OUT_SP_V0_LABEL for labeled silent payment and PSBT_OUT_BIP32_DERIVATION for change identification"
"Valid PSBT demonstrating BIP-352 label=0 convention for silent payments change where output 0 (recipient) has no PSBT_OUT_SP_V0_LABEL field and output 1 (change) has PSBT_OUT_SP_V0_LABEL=0"
"Valid PSBT with multiple silent payment outputs to the same scan key, using different k values to generate distinct output scripts"
"Valid PSBT with mixed input types where only eligible P2WPKH inputs contribute ECDH shares (ineligible P2SH multisig excluded)"
```

### Generating Test Vectors

Test vectors were generated using [test_generator.py](https://github.com/macgyver13/bip375-examples/blob/main/python/tests/test_generator.py)

### Run Tests

```bash
python test_runner.py                    # Run all tests
python test_runner.py -v                 # Verbose mode with detailed "Validation Result"
```

## Validation Layers

The validator implements progressive validation:
1. **PSBT Structure** - Parse PSBT v2 format
2. **Input Eligibility** - Validate eligible input types (P2PKH, P2WPKH, P2TR, P2SH-P2WPKH)
3. **DLEQ Proofs** - Verify ECDH share correctness using BIP-374
4. **Output Fields** - Check PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO requirements
5. **BIP-352 Outputs** - Validate output scripts match expected silent payment addresses