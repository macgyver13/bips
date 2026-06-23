# BIP-375 Validation Reference

A reference validation implementation for BIP-375: Sending Silent Payments with PSBTs.

## Core Files

- **`validator/bip352_crypto.py`** - Silent payment output script derivation
- **`validator/inputs.py`** - PSBT input utility functions
- **`validator/psbt_bip375.py`** - BIP-375 specific PSBT/PSBTMap extensions
- **`validator/validate_psbt.py`** - Main BIP-375 validation functions
- **`workflow/roles.py`** - Reference PSBT v2 role functions for the silent payment workflow
- **`workflow/validate_workflow.py`** - Step-by-step workflow validation against test vectors
- **`test_runner.py`** - Validation test infrastructure (executable)

## Workflow

`workflow/roles.py` implements the PSBT v2 role pipeline for silent payments:

```text
Creator → Constructor → Updater → SP Output Finalizer → Signer → Input Finalizer → Extractor
```

Each role is a function that takes a PSBT and returns the next-step PSBT
(`create_psbt`, `construct_sp_psbt`, `update_sp_psbt`, `finalize_sp_outputs`,
`sign_sp_psbt`, `finalize_sp_inputs`, `extract_sp_transaction`). The Updater
produces either a single global ECDH share (when one party holds every input key)
or per-input shares that combine across successive updates (the multi-party case).

`detect_psbt_step()` infers a PSBT's current step (`PSBTState`) from its contents, and each role validates the incoming step before running, raising
`InvalidStateTransitionError` on an out-of-order call.

## Dependencies

- **`deps/bitcoin_test/psbt.py`** - Bitcoin test framework PSBT module - [PR #21283](https://github.com/bitcoin/bitcoin/pull/21283)
- **`deps/bitcoin_test/messages.py`** - Bitcoin test framework primitives and message structures
- **`deps/bitcoin_test/transaction.py`** - Transaction primitives (CTransaction, CTxIn, CTxOut, COutPoint)
- **`deps/bitcoin_test/sighash.py`** - Sighash computation (SegwitV0/Taproot)
- **`deps/bitcoin_test/signing.py`** - Key types (ECKey, ECPubKey)
- **`deps/bitcoin_test/utils.py`** - Serialization helpers and script type checks
- **`deps/dleq.py`** - Reference DLEQ implementation from BIP-374
- **`deps/secp256k1lab/`** - vendored copy of [secp256k1lab](https://github.com/secp256k1lab/secp256k1lab/commit/44dc4bd893b8f03e621585e3bf255253e0e0fbfb) library at version 1.0.0

## Testing

### Run Tests

```bash
python test_runner.py                    # Run all validation tests
python test_runner.py --invalid          # Run only the invalid PSBT section
python test_runner.py --valid            # Run only the valid PSBT section
python test_runner.py --workflow         # Run only the step-by-step role workflow section
python test_runner.py --valid --invalid  # Run a subset (any combination of flags)

python test_runner.py -v                 # Verbose mode with detailed validation status
python test_runner.py -vv                # More verbose with validation check failure reason

python test_runner.py -f vectors.json    # Use custom test vector file
```

### Generating Test Vectors

Test vectors were generated using [test_generator.py](https://github.com/macgyver13/bip375-test-generator/)
