# BIP-375 Validation Reference

A reference validation implementation for BIP-375: Sending Silent Payments with PSBTs.

## Core Files
- **`validator/bip352_crypto.py`** - Silent payment output script derivation
- **`validator/inputs.py`** - PSBT input utility functions
- **`validator/psbt_bip375.py`** - BIP-375 specific PSBT/PSBTMap extensions
- **`validator/validate_psbt.py`** - Main BIP-375 validation functions
- **`test_runner.py`** - Test infrastructure (executable)
- **`workflow/sp_signer.py`** - BIP-375 Signer through the output scripts, without transaction signatures
- **`workflow/validate_workflow.py`** - Per-task checks for the vector file

## What the runner checks

For `create`, `expected.psbt` must pass the BIP-375 checks. For `update`, both the incoming PSBT and `expected.psbt` must pass. Nothing is rebuilt. For `sign`, the runner adds this signer's ECDH shares, DLEQ proofs and output scripts and compares those fields to `expected.psbt`. `expected.psbt` must also pass the checks. Its other fields are taken as given. For `finalize`, output maps and outpoints are unchanged and `expected.psbt` still passes the checks, including on a finalized PSBT. For `extract`, the finalized PSBT passes the checks and `expected.tx` carries the verified silent payment output scripts and the PSBT's outpoints. Final scripts and transaction signatures are not rebuilt here. [bip375-test-generator](https://github.com/macgyver13/bip375-test-generator/) checks those before it emits a vector. A full create-to-extract flow, including hardware signers, is in [bip375-examples](https://github.com/macgyver13/bip375-examples/).

## Dependencies
- **`deps/bitcoin_test/psbt.py`** - Bitcoin test framework PSBT module - [PR #21283](https://github.com/bitcoin/bitcoin/pull/21283)
- **`deps/bitcoin_test/messages.py`** - Bitcoin test framework primitives and message structures
- **`deps/bitcoin_test/crypto/ripemd160.py`** - pure-Python RIPEMD-160 for hash160, from Bitcoin Core `7988380da9`
- **`deps/dleq.py`** - Reference DLEQ implementation from BIP-374
- **`deps/secp256k1lab/`** - vendored copy of [secp256k1lab](https://github.com/secp256k1lab/secp256k1lab/commit/44dc4bd893b8f03e621585e3bf255253e0e0fbfb) library at version 1.0.0

## Test Vector Format

Each vector is a base64 PSBT with a `description`, a `task`, and a `supplementary` field:

- `task` - the outcome a runner should expect. `invalid` vectors use
  `fail_deserialize` (must be rejected by the PSBT Structure check), `fail_sign` or
  `fail_extract` (must pass PSBT Structure and be rejected by a later check). `fail_extract`
  is a finalized PSBT. `valid` vectors use
  `finalize` (fully signed, ready to finalize), `sign` (a valid but not-yet-signed
  or partially-signed snapshot) or `deserialize` (valid, with no signing expected).
- `supplementary` - diagnostic material (`inputs`, `outputs`, `sp_proofs`, and
  `psbt_unique_id`) not used for validation:
  - `inputs` - `prevout_txid` is in display (RPC, big-endian) byte order, not the
    internal little-endian order PSBT fields use. Every entry in `supplementary.inputs`
    carries its full `non_witness_utxo` (the previous transaction), and some also
    carry `witness_utxo`.
  - `psbt_unique_id` - on every `valid` vector, the PSBT's unique identifier as
    described in the BIP's Unique Identification section, in display byte order.

The top-level `wallets` field lists the two BIP-39 test wallets the input keys come
from, by fingerprint and mnemonic. The first is the primary wallet. It also holds the
silent payment scan and spend keys. `notes` gives the derivation paths.

## Testing

### Run Tests

```bash
python test_runner.py                    # Run all tests
python test_runner.py -v                 # Verbose mode with detailed validation status
python test_runner.py -vv                # More verbose with validation check failure reason

python test_runner.py -f vectors.json    # Use custom test vector file
```

### Generating Test Vectors

Test vectors were generated using [test_generator.py](https://github.com/macgyver13/bip375-test-generator/)
