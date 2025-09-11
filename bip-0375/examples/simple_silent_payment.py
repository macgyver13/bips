#!/usr/bin/env python3
"""
BIP 375 Example: Simple Silent Payment

Demonstrates the basic flow of creating a PSBT v2 transaction
that sends to a silent payment address using a single signer.

This example shows:
- Creating a PSBT with silent payment outputs
- Computing ECDH shares for the silent payment
- Generating DLEQ proofs for verification
- Computing the final output scripts
- Extracting the completed transaction
"""

import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reference import (
    SilentPaymentPSBT,
    SilentPaymentAddress,
    ECDHShare
)

def create_simple_silent_payment():
    """
    Create a simple silent payment transaction
    Single input -> Single silent payment output + change
    """
    
    print("BIP 375 Example: Simple Silent Payment")
    print("=" * 50)
    
    # Step 1: Create silent payment address (normally provided by recipient)
    print("\n1. Creating recipient silent payment address...")
    recipient_address = SilentPaymentAddress(
        scan_key=bytes.fromhex("02a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a"),
        spend_key=bytes.fromhex("03b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab1")
    )
    print(f"Scan key: {recipient_address.scan_key.hex()}")
    print(f"Spend key: {recipient_address.spend_key.hex()}")
    
    # Step 2: Define transaction inputs
    print("\n2. Defining transaction inputs...")
    inputs = [
        {
            "txid": "1234567890abcdef" * 4,  # 32-byte txid
            "vout": 0,
            "amount": 100000,  # 100,000 sats
            "script_pubkey": "0014" + "abcd1234" * 5,  # P2WPKH
            "private_key": bytes.fromhex("d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")
        }
    ]
    print(f"Input: {inputs[0]['txid'][:8]}...:{inputs[0]['vout']} ({inputs[0]['amount']} sats)")
    
    # Step 3: Define regular outputs (change)
    print("\n3. Defining regular outputs...")
    regular_outputs = [
        {
            "amount": 50000,  # 50,000 sats change
            "script_pubkey": "0014" + "1234abcd" * 5  # P2WPKH change
        }
    ]
    print(f"Change output: {regular_outputs[0]['amount']} sats")
    
    # Step 4: Calculate silent payment amount
    silent_amount = inputs[0]["amount"] - regular_outputs[0]["amount"] - 1000  # minus fee
    print(f"Silent payment amount: {silent_amount} sats")
    
    try:
        # Step 5: Create PSBT with silent payment
        print("\n5. Creating PSBT with silent payment...")
        psbt = SilentPaymentPSBT()
        
        # This would normally call the implemented function
        # psbt = psbt.create_silent_payment_psbt(inputs, regular_outputs, [recipient_address])
        print("⚠️  create_silent_payment_psbt() not yet implemented")
        
        # Step 6: Add ECDH shares
        print("\n6. Computing ECDH shares...")
        private_keys = {0: inputs[0]["private_key"]}  # Input index -> private key
        scan_keys = [recipient_address.scan_key]
        
        # This would normally call the implemented function
        # psbt.add_ecdh_shares(private_keys, scan_keys)
        print("⚠️  add_ecdh_shares() not yet implemented")
        
        # Step 7: Generate DLEQ proofs
        print("\n7. Generating DLEQ proofs...")
        # psbt.generate_dleq_proofs(private_keys)
        print("⚠️  generate_dleq_proofs() not yet implemented")
        
        # Step 8: Verify DLEQ proofs
        print("\n8. Verifying DLEQ proofs...")
        # is_valid = psbt.verify_dleq_proofs()
        print("⚠️  verify_dleq_proofs() not yet implemented")
        
        # Step 9: Compute output scripts
        print("\n9. Computing silent payment output scripts...")
        # psbt.compute_output_scripts()
        print("⚠️  compute_output_scripts() not yet implemented")
        
        # Step 10: Extract final transaction
        print("\n10. Extracting final transaction...")
        # transaction_bytes = psbt.extract_transaction()
        print("⚠️  extract_transaction() not yet implemented")
        
        print("\n✅ Simple silent payment flow completed successfully!")
        print("(Note: Functions are stubbed - implementation needed)")
        
    except NotImplementedError as e:
        print(f"\n⚠️  Implementation needed: {e}")
    except Exception as e:
        print(f"\n❌ Error: {e}")

def demonstrate_global_vs_per_input():
    """
    Demonstrate the difference between global and per-input ECDH shares
    """
    print("\n" + "=" * 50)
    print("Global vs Per-Input ECDH Shares")
    print("=" * 50)
    
    print("\nScenario: Same transaction, different ECDH approaches")
    
    # Multi-input transaction
    inputs = [
        {"private_key": "a1", "amount": 50000},
        {"private_key": "a2", "amount": 30000}
    ]
    
    scan_key = "B_scan"
    
    print(f"\nInputs: {len(inputs)} inputs with private keys a1, a2")
    print(f"Scan key: {scan_key}")
    
    print("\n--- Global ECDH Approach ---")
    print("Use when: Single entity controls ALL private keys")
    print("Process:")
    print("1. Sum private keys: a_total = a1 + a2")
    print("2. Single ECDH computation: C_global = a_total * B_scan")
    print("3. Single DLEQ proof for a_total")
    print("Benefits: Efficient, smaller PSBT, private")
    
    print("\n--- Per-Input ECDH Approach ---") 
    print("Use when: Different entities control different inputs")
    print("Process:")
    print("1. Input 0: C1 = a1 * B_scan + DLEQ proof for a1")
    print("2. Input 1: C2 = a2 * B_scan + DLEQ proof for a2")
    print("3. Final result: C_total = C1 + C2")
    print("Benefits: Collaborative, verifiable, flexible")

if __name__ == "__main__":
    create_simple_silent_payment()
    demonstrate_global_vs_per_input()