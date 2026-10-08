# BIP-375 Validation Reference

A reference validation implementation for BIP-375: Sending Silent Payments with PSBTs.

## Core Files
- **`validator/bip352_crypto.py`** - Silent payment output script derivation
- **`validator/inputs.py`** - PSBT input utility functions
- **`validator/psbt_bip375.py`** - BIP-375 specific PSBT/PSBTMap extensions
- **`validator/validate_psbt.py`** - Main BIP-375 validation functions, `run_checks` and `validate_bip375_psbt`
- **`workflow/roles.py`** - Reference PSBT v2 roles (Creator through Extractor)
- **`workflow/validate_workflow.py`** - Drives the roles against the `valid` and `workflows` test vectors
- **`test_runner.py`** - Test infrastructure (executable)

## Dependencies
- **`deps/bitcoin_test/psbt.py`** - Bitcoin test framework PSBT module - [PR #21283](https://github.com/bitcoin/bitcoin/pull/21283)
- **`deps/bitcoin_test/messages.py`** - Bitcoin test framework primitives and message structures
- **`deps/bitcoin_test/script.py`** - Bitcoin test framework CScript, legacy, BIP-143 and BIP-341 sighash, and `hash160`
- **`deps/bitcoin_test/script_util.py`** - Bitcoin test framework P2PKH, P2WPKH and P2SH-P2WPKH script builders
- **`deps/bitcoin_test/key.py`** - Bitcoin test framework ECDSA signing key
- **`deps/bitcoin_test/util.py`** - Bitcoin test framework `assert_equal`, used by the three above
- **`deps/bitcoin_test/crypto/ripemd160.py`** - Bitcoin test framework RIPEMD-160, used by `hash160`
- **`deps/dleq.py`** - Reference DLEQ implementation from BIP-374
- **`deps/secp256k1lab/`** - vendored copy of [secp256k1lab](https://github.com/secp256k1lab/secp256k1lab/commit/44dc4bd893b8f03e621585e3bf255253e0e0fbfb) library at version 1.0.0

`script.py`, `script_util.py`, `key.py` and `util.py` are trimmed from Bitcoin
Core's `test/functional/test_framework` at commit 7988380da9: every definition
they keep is verbatim, and each file's header lists what changed (the imports,
and in `key.py` two `ECPubKey` methods removed because secp256k1lab differs from
Core's curve module there). `crypto/ripemd160.py` is unmodified from the same
commit; Core uses it because `hashlib` does not provide RIPEMD-160 on every
OpenSSL build.

## Test Vector Format

Each vector's `supplementary` block carries diagnostic material and is not itself
validated; only the base64/hex PSBT is:

- **`hex`** - the PSBT re-encoded as hex, alongside the base64 string
- **`task`** - the outcome a runner should expect. `invalid` vectors use
  `fail_deserialize` (must be rejected by the PSBT Structure check) or `fail_sign`
  (must pass PSBT Structure and be rejected by a later check). `valid` vectors use
  `deserialize` (validated only), `finalize` (fully signed, ready to finalize) or
  `sign` (a valid but not-yet-signed or partially-signed snapshot). `test_runner.py`'s `run_invalid_tests` gates on
  `task` to confirm each invalid vector fails at the check its category implies, not
  just that it fails somewhere.
- **`inputs`** - `prevout_txid` is in display (RPC, big-endian) byte order, not the
  internal little-endian order PSBT fields use. Every input carries its full
  `non_witness_utxo` (the previous transaction) in addition to `witness_utxo`.

## Role Workflow

`workflow/roles.py` implements the PSBT v2 roles for silent payments: Creator,
Constructor, Updater, Signer, Input Finalizer and Extractor. Each role checks its
own preconditions from the PSBT's contents. The Signer signs P2PKH, P2WPKH and
P2TR key-path inputs and raises `NotImplementedError` for any other input it
holds a key for (see the module docstring).

`workflow/validate_workflow.py`'s `run_vector` drives a vector through the role
its `task` names. It serves both the one-shot `valid` vectors and the top-level
`workflows` array, where each entry is one step of a scenario (`create`,
`update`, `sign`, `finalize`, `extract`):

- the incoming `psbt` must pass validation (a `create` step builds its PSBT from
  `supplementary` alone, and a `deserialize` vector is validated only)
- the role's result must match `expected.psbt` field by field, or for `extract`,
  the raw transaction must match `expected.tx`
- where a step carries `expected.transaction_id`, the BIP-375 unique identifier
  of its result must match it; every step of a workflow shares the same one
- the result must pass validation, and a `finalize` result must also extract,
  since the Input Finalizer prunes fields the validator otherwise reads

A `sign` step's `supplementary.dleq_aux_rand` discloses the 32-byte randomness
each DLEQ proof the step contributes must use (`{scan_key, input_index?,
aux_rand}`), so the reference Signer's own proofs are compared to
`expected.psbt` like every other field.

## Testing

### Run Tests

```bash
python test_runner.py                    # Run every section: invalid, valid, workflow
python test_runner.py -s invalid         # Run one section (repeatable)
python test_runner.py -v                 # Verbose mode with detailed validation status
python test_runner.py -vv                # More verbose with validation check failure reason

python test_runner.py -f vectors.json    # Use custom test vector file
```

### Generating Test Vectors

Test vectors were generated using [test_generator.py](https://github.com/macgyver13/bip375-test-generator/)
