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
from psbt_sp.psbt import SilentPaymentAddress, SilentPaymentPSBT
from psbt_sp.crypto import Wallet, UTXO


def create_simple_silent_payment() -> SilentPaymentPSBT:
    """
    Create a simple silent payment transaction
    Single input -> Single silent payment output + change
    """
    
    print("BIP 375 Example: Simple Silent Payment")
    print("=" * 50)

    wallet = Wallet()
    
    # Setup: Create silent payment address (normally provided by recipient)
    print("\nSetup: Creating recipient silent payment address...")
    recipient_address = SilentPaymentAddress(
        scan_key=wallet.scan_pub,
        spend_key=wallet.spend_pub
    )
    print(f"Scan key: {recipient_address.scan_key.hex}")
    print(f"Spend key: {recipient_address.spend_key.hex}")
    
    print("\nDefining transaction inputs...")
    inputs = [
        UTXO(
            txid="1234567890abcdef" * 4,
            vout=0,
            amount=100000,
            script_pubkey="0014" + "abcd1234" * 5,
            private_key=wallet.input_key_pair(0)[0]
        )
    ]
    print(f"Input: {inputs[0].txid_bytes[:8].hex()}...:{inputs[0].vout} ({inputs[0].amount} sats)")
    
    print("\nDefining regular outputs + change...")
    regular_outputs = [
        {
            "amount": 50000,  # 50,000 sats change
            "script_pubkey": "0014" + "1234abcd" * 5  # P2WPKH change
        }
    ]
    print(f"Change output: {regular_outputs[0]['amount']} sats")
    
    # Calculate silent payment amount
    silent_amount = inputs[0].amount - regular_outputs[0]["amount"] - 1000  # minus fee
    print(f"Silent payment amount: {silent_amount} sats")
    
    print("\n1+2. (CREATOR + CONSTRUCTOR) Creating PSBT with silent payment...")
    psbt = SilentPaymentPSBT()
    outputs = regular_outputs + [{"amount": silent_amount, "address": recipient_address}]
    psbt.create_silent_payment_psbt(inputs, outputs)
    print("\n3. (UPDATER) Optional: Add BIP32_DERIVATION + SP_VO_LABEL")
    # TODO: Add BIP32_DERIVATION + SP_VO_LABEL - https://bips.xyz/375#updater
    
    print("\n4. (SIGNER) ECDH + verify + scripts + flags + sign")
    # SIGNER ROLE - Complete BIP 375 compliant workflow:
    # - Compute ECDH shares and DLEQ proofs
    # - Verify all DLEQ proofs
    # - Compute output scripts
    # - Set modifiable flags to False
    # - Add signatures
    success = psbt.signer_role(inputs, [recipient_address.scan_key])
    if not success:
        print("❌ SIGNER role failed")

    print("\n5. (EXTRACTOR) Extracting final transaction...")
    transaction_bytes = psbt.extract_transaction()
    print(f"\n Final transaction: {transaction_bytes.hex()}")
    return psbt


if __name__ == "__main__":
    psbt = create_simple_silent_payment()
    print()
    print(psbt.pretty_print())
    print("\nPSBT:", psbt.encode())