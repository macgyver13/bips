#!/usr/bin/env python3
# Copyright (c) 2014-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpful routines for regression testing."""
#
# Trimmed from Bitcoin Core test/functional/test_framework/util.py at 7988380da9
# for the BIP-375 reference. Every definition below is verbatim from that
# file; definitions it does not need are removed. Changed: the imports (none
# of the kept definitions use any).
#



def summarise_dict_differences(thing1, thing2):
    if not isinstance(thing1, dict) or not isinstance(thing2, dict):
        return thing1, thing2
    d1, d2 = {}, {}
    for k in sorted(thing1.keys()):
        if k not in thing2:
            d1[k] = thing1[k]
        elif thing1[k] != thing2[k]:
            d1[k], d2[k] = summarise_dict_differences(thing1[k], thing2[k])
    for k in sorted(thing2.keys()):
        if k not in thing1:
            d2[k] = thing2[k]
    return d1, d2

def assert_equal(thing1, thing2, *args):
    if thing1 != thing2 and not args and isinstance(thing1, dict) and isinstance(thing2, dict):
        d1,d2 = summarise_dict_differences(thing1, thing2)
        if d1 != thing1 or d2 != thing2:
            raise AssertionError(f"not({thing1!s} == {thing2!s})\n  in particular not({d1!s} == {d2!s})")
        else:
            raise AssertionError(f"not({thing1!s} == {thing2!s})")
    if thing1 != thing2 or any(thing1 != arg for arg in args):
        raise AssertionError("not(%s)" % " == ".join(str(arg) for arg in (thing1, thing2) + args))
