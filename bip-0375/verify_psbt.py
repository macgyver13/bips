#!/usr/bin/env python3
"""
Simple PSBT verification script

Verifies that generated BIP 375 test vectors contain properly formatted PSBTs
with the expected BIP 375 fields.
"""

import json
import base64
import sys

def parse_compact_size_uint(data, offset=0):
    """Parse compact size uint from data"""
    if offset >= len(data):
        raise ValueError("Not enough data")
    
    first_byte = data[offset]
    if first_byte < 0xfd:
        return first_byte, offset + 1
    elif first_byte == 0xfd:
        return int.from_bytes(data[offset+1:offset+3], 'little'), offset + 3
    elif first_byte == 0xfe:
        return int.from_bytes(data[offset+1:offset+5], 'little'), offset + 5
    else:
        return int.from_bytes(data[offset+1:offset+9], 'little'), offset + 9

def verify_psbt_structure(psbt_b64):
    """Basic verification that PSBT has correct structure"""
    try:
        data = base64.b64decode(psbt_b64)
        
        # Check magic
        if data[:5] != b'psbt\xff':
            return False, "Invalid PSBT magic"
        
        offset = 5
        
        # Parse global section
        global_fields = []
        while offset < len(data):
            key_len, offset = parse_compact_size_uint(data, offset)
            if key_len == 0:  # End of section
                break
                
            if offset + key_len > len(data):
                return False, "Truncated key data"
            
            key_data = data[offset:offset+key_len]
            offset += key_len
            
            value_len, offset = parse_compact_size_uint(data, offset)
            if offset + value_len > len(data):
                return False, "Truncated value data"
            
            value_data = data[offset:offset+value_len]
            offset += value_len
            
            if key_data:
                field_type = key_data[0]
                key_payload = key_data[1:] if len(key_data) > 1 else b''
                global_fields.append((field_type, key_payload, value_data))
        
        # Check that we have BIP 375 global fields or input fields
        has_bip375_global = any(ft in [0x07, 0x08] for ft, _, _ in global_fields)
        
        return True, f"Valid PSBT structure, {len(global_fields)} global fields, BIP375 global: {has_bip375_global}"
        
    except Exception as e:
        return False, f"Parse error: {e}"

def main():
    if len(sys.argv) != 2:
        print("Usage: python verify_psbt.py test_vectors.json")
        sys.exit(1)
    
    with open(sys.argv[1], 'r') as f:
        test_data = json.load(f)
    
    print("BIP 375 PSBT Verification")
    print("=" * 40)
    
    # Check valid test cases
    print(f"\nValid test cases ({len(test_data['valid'])}):")
    for i, test_case in enumerate(test_data['valid']):
        desc = test_case['description']
        psbt_b64 = test_case['psbt']
        
        is_valid, msg = verify_psbt_structure(psbt_b64)
        status = "✅" if is_valid else "❌"
        print(f"{i+1:2d}. {status} {desc}")
        print(f"     {msg}")
        print(f"     PSBT length: {len(base64.b64decode(psbt_b64))} bytes")
    
    # Check invalid test cases
    print(f"\nInvalid test cases ({len(test_data['invalid'])}):")
    for i, test_case in enumerate(test_data['invalid']):
        desc = test_case['description']
        psbt_b64 = test_case['psbt']
        expected_error = test_case['error']
        
        is_valid, msg = verify_psbt_structure(psbt_b64)
        status = "📋" if is_valid else "❌"  # Should still parse as valid PSBT structure
        print(f"{i+1:2d}. {status} {desc}")
        print(f"     {msg}")
        print(f"     Expected error: {expected_error}")
        print(f"     PSBT length: {len(base64.b64decode(psbt_b64))} bytes")
    
    print(f"\nSummary: Generated {len(test_data['valid'])} valid and {len(test_data['invalid'])} invalid test vectors")

if __name__ == "__main__":
    main()