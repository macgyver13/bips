#!/usr/bin/env python3
"""
PSBT v2 utilities for BIP 375

Helper functions for creating, serializing, and parsing PSBT v2 transactions
with BIP 375 silent payment extensions.
"""

import struct
from typing import Dict, List, Optional, Tuple
from secp256k1 import ECKey, ECPubKey, TaggedHash

def compact_size_uint(n: int) -> bytes:
    """Encode integer as Bitcoin compact size uint"""
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<L', n)
    else:
        return b'\xff' + struct.pack('<Q', n)

def read_compact_size_uint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Read compact size uint from bytes, return (value, new_offset)"""
    if offset >= len(data):
        raise ValueError("Not enough data")
    
    first_byte = data[offset]
    if first_byte < 0xfd:
        return first_byte, offset + 1
    elif first_byte == 0xfd:
        if offset + 3 > len(data):
            raise ValueError("Not enough data")
        return struct.unpack('<H', data[offset+1:offset+3])[0], offset + 3
    elif first_byte == 0xfe:
        if offset + 5 > len(data):
            raise ValueError("Not enough data")
        return struct.unpack('<L', data[offset+1:offset+5])[0], offset + 5
    else:  # 0xff
        if offset + 9 > len(data):
            raise ValueError("Not enough data")
        return struct.unpack('<Q', data[offset+1:offset+9])[0], offset + 9

def write_keydata(key_data: bytes) -> bytes:
    """Write key data with length prefix"""
    return compact_size_uint(len(key_data)) + key_data

def write_valuedata(value_data: bytes) -> bytes:
    """Write value data with length prefix"""
    return compact_size_uint(len(value_data)) + value_data

def write_psbt_field(field_type: int, key_data: bytes, value_data: bytes) -> bytes:
    """Write a PSBT field in the format: key_len + field_type + key_data + value_len + value_data"""
    key_full = bytes([field_type]) + key_data
    return write_keydata(key_full) + write_valuedata(value_data)

def ser_uint32(n: int) -> bytes:
    """Serialize 32-bit unsigned integer in little-endian"""
    return struct.pack('<I', n)

def get_input_hash(outpoints: List[bytes], sum_input_pubkeys: ECPubKey) -> bytes:
    """Compute input hash as defined in BIP 352"""
    # Sort outpoints
    sorted_outpoints = sorted(outpoints)
    lowest_outpoint = sorted_outpoints[0]
    
    return TaggedHash("BIP0352/Inputs", lowest_outpoint + sum_input_pubkeys.get_bytes(bip340=False))

def create_silent_payment_tweak(input_hash: bytes, ecdh_shared_secret: bytes, k: int) -> bytes:
    """Create silent payment tweak using BIP 352 protocol"""
    return TaggedHash("BIP0352/SharedSecret", ecdh_shared_secret + ser_uint32(k))

class PSBTField:
    """Represents a single PSBT field"""
    
    def __init__(self, field_type: int, key_data: bytes, value_data: bytes):
        self.field_type = field_type
        self.key_data = key_data
        self.value_data = value_data
    
    def serialize(self) -> bytes:
        """Serialize this field to PSBT format"""
        return write_psbt_field(self.field_type, self.key_data, self.value_data)

class PSBTv2:
    """
    Basic PSBT v2 implementation for BIP 375 test vector generation
    """
    
    def __init__(self):
        self.global_fields: List[PSBTField] = []
        self.input_maps: List[List[PSBTField]] = []
        self.output_maps: List[List[PSBTField]] = []
    
    def add_global_field(self, field_type: int, key_data: bytes, value_data: bytes):
        """Add a global field"""
        self.global_fields.append(PSBTField(field_type, key_data, value_data))
    
    def add_input_field(self, input_index: int, field_type: int, key_data: bytes, value_data: bytes):
        """Add a field to specific input"""
        # Extend input_maps if needed
        while len(self.input_maps) <= input_index:
            self.input_maps.append([])
        
        self.input_maps[input_index].append(PSBTField(field_type, key_data, value_data))
    
    def add_output_field(self, output_index: int, field_type: int, key_data: bytes, value_data: bytes):
        """Add a field to specific output"""
        # Extend output_maps if needed
        while len(self.output_maps) <= output_index:
            self.output_maps.append([])
        
        self.output_maps[output_index].append(PSBTField(field_type, key_data, value_data))
    
    def serialize_section(self, fields: List[PSBTField]) -> bytes:
        """Serialize a section (global, input, or output)"""
        result = b''
        for field in fields:
            result += field.serialize()
        # End with separator (empty key)
        result += b'\x00'
        return result
    
    def serialize(self) -> bytes:
        """Serialize entire PSBT to bytes"""
        result = b'psbt\xff'  # PSBT magic
        
        # Global section
        result += self.serialize_section(self.global_fields)
        
        # Input sections
        for input_fields in self.input_maps:
            result += self.serialize_section(input_fields)
        
        # Output sections  
        for output_fields in self.output_maps:
            result += self.serialize_section(output_fields)
        
        return result

# PSBT v2 field types
class PSBTv2FieldType:
    # Global fields
    PSBT_GLOBAL_VERSION = 0x00
    PSBT_GLOBAL_TX_VERSION = 0x02
    PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03
    PSBT_GLOBAL_INPUT_COUNT = 0x04
    PSBT_GLOBAL_OUTPUT_COUNT = 0x05
    PSBT_GLOBAL_TX_MODIFIABLE = 0x06
    
    # BIP 375 global fields
    PSBT_GLOBAL_SP_ECDH_SHARE = 0x07
    PSBT_GLOBAL_SP_DLEQ = 0x08
    
    # Input fields
    PSBT_IN_PREVIOUS_TXID = 0x0e
    PSBT_IN_OUTPUT_INDEX = 0x0f
    PSBT_IN_SEQUENCE = 0x10
    PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12
    PSBT_IN_WITNESS_UTXO = 0x01
    PSBT_IN_PARTIAL_SIG = 0x02
    PSBT_IN_SIGHASH_TYPE = 0x03
    PSBT_IN_BIP32_DERIVATION = 0x06
    
    # BIP 375 input fields
    PSBT_IN_SP_ECDH_SHARE = 0x1d
    PSBT_IN_SP_DLEQ = 0x1e
    
    # Output fields
    PSBT_OUT_OUTPUT_SCRIPT = 0x13
    PSBT_OUT_AMOUNT = 0x14
    PSBT_OUT_BIP32_DERIVATION = 0x15
    
    # BIP 375 output fields  
    PSBT_OUT_SP_V0_INFO = 0x09
    PSBT_OUT_SP_V0_LABEL = 0x0a

def create_outpoint(txid: bytes, vout: int) -> bytes:
    """Create a Bitcoin outpoint (32 byte txid + 4 byte vout)"""
    return txid + struct.pack('<I', vout)

def create_witness_utxo(amount: int, script_pubkey: bytes) -> bytes:
    """Create witness UTXO field value"""
    return struct.pack('<Q', amount) + compact_size_uint(len(script_pubkey)) + script_pubkey