#!/usr/bin/env python3
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Useful Script constants and utils."""
#
# Trimmed from Bitcoin Core test/functional/test_framework/script_util.py at
# 7988380da9 for the BIP-375 reference. Every definition below is verbatim from
# that file; definitions it does not need are removed. Changed: the imports
# (only the names the kept definitions use).
#

from .script import (
    CScript,
    OP_0,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    hash160,
)

from .util import assert_equal

def keyhash_to_p2pkh_script(hash):
    assert_equal(len(hash), 20)
    return CScript([OP_DUP, OP_HASH160, hash, OP_EQUALVERIFY, OP_CHECKSIG])

def scripthash_to_p2sh_script(hash):
    assert_equal(len(hash), 20)
    return CScript([OP_HASH160, hash, OP_EQUAL])

def key_to_p2pkh_script(key):
    key = check_key(key)
    return keyhash_to_p2pkh_script(hash160(key))

def script_to_p2sh_script(script):
    script = check_script(script)
    return scripthash_to_p2sh_script(hash160(script))

def key_to_p2sh_p2wpkh_script(key):
    key = check_key(key)
    p2shscript = CScript([OP_0, hash160(key)])
    return script_to_p2sh_script(p2shscript)

def program_to_witness_script(version, program):
    if isinstance(program, str):
        program = bytes.fromhex(program)
    assert 0 <= version <= 16
    assert 2 <= len(program) <= 40
    assert version > 0 or len(program) in [20, 32]
    return CScript([version, program])

def key_to_p2wpkh_script(key):
    key = check_key(key)
    return program_to_witness_script(0, hash160(key))

def check_key(key):
    if isinstance(key, str):
        key = bytes.fromhex(key)  # Assuming this is hex string
    if isinstance(key, bytes) and (len(key) == 33 or len(key) == 65):
        return key
    assert False

def check_script(script):
    if isinstance(script, str):
        script = bytes.fromhex(script)  # Assuming this is hex string
    if isinstance(script, bytes) or isinstance(script, CScript):
        return script
    assert False
