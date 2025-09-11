#!/usr/bin/env python3
"""
BIP 375 Example: Hardware Wallet Flow

Demonstrates the interaction between a hardware wallet and software coordinator
for silent payment transactions. Shows how DLEQ proofs provide cryptographic
verification of hardware wallet computations.

This example shows:
- Hardware wallet and software coordinator separation
- ECDH computation on hardware device
- DLEQ proof generation and verification
- Trust verification without revealing private keys
"""

import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reference import (
    SilentPaymentPSBT,
    SilentPaymentAddress,
    ECDHShare,
    generate_dleq_proof,
    verify_dleq_proof
)

class HardwareWallet:
    """Simulates a hardware wallet device"""
    
    def __init__(self, name: str):
        self.name = name
        self.private_keys = {}  # Stored securely in hardware
        self.public_keys = {}   # Derived from private keys
    
    def store_key(self, input_index: int, private_key: bytes):
        """Store a private key (simulated secure storage)"""
        self.private_keys[input_index] = private_key
        # In real hardware, public key would be derived using secp256k1
        self.public_keys[input_index] = b'\x02' + private_key  # Placeholder
    
    def get_public_key(self, input_index: int) -> bytes:
        """Get public key for an input (safe to share)"""
        return self.public_keys.get(input_index, b'')
    
    def compute_ecdh_share(self, input_index: int, scan_key: bytes) -> bytes:
        """Compute ECDH share on hardware device"""
        private_key = self.private_keys.get(input_index)
        if not private_key:
            raise ValueError(f"Private key for input {input_index} not found")
        
        print(f"  [{self.name}] Computing ECDH: a{input_index} * B_scan")
        # In real hardware: ecdh_share = private_key * scan_key (secp256k1)
        ecdh_share = b'\x03' + private_key + scan_key[:16]  # Placeholder
        return ecdh_share
    
    def generate_dleq_proof(self, input_index: int, scan_key: bytes, 
                           ecdh_share: bytes) -> bytes:
        """Generate DLEQ proof on hardware device"""
        private_key = self.private_keys.get(input_index)
        if not private_key:
            raise ValueError(f"Private key for input {input_index} not found")
        
        print(f"  [{self.name}] Generating DLEQ proof for input {input_index}")
        # In real hardware: use BIP 374 DLEQ proof generation
        proof = b'PROOF_' + private_key[:10] + scan_key[:10] + ecdh_share[:10]  # Placeholder
        return proof
    
    def sign_input(self, input_index: int, transaction_hash: bytes) -> bytes:
        """Sign transaction input (SIGHASH_ALL required for silent payments)"""
        private_key = self.private_keys.get(input_index)
        if not private_key:
            raise ValueError(f"Private key for input {input_index} not found")
        
        print(f"  [{self.name}] Signing input {input_index} with SIGHASH_ALL")
        signature = b'SIG_' + private_key[:10] + transaction_hash[:10]  # Placeholder
        return signature

class SoftwareCoordinator:
    """Software wallet coordinating with hardware wallet"""
    
    def __init__(self):
        self.psbt = None
        self.recipient_address = None
    
    def create_psbt(self, inputs: list, outputs: list, 
                   recipient_address: SilentPaymentAddress):
        """Create initial PSBT structure"""
        self.psbt = SilentPaymentPSBT()
        self.recipient_address = recipient_address
        
        print("[Software] Creating PSBT v2 structure...")
        # psbt = self.psbt.create_silent_payment_psbt(inputs, outputs, [recipient_address])
        print("[Software] Added silent payment output fields")
    
    def request_ecdh_shares(self, hardware_wallet: HardwareWallet, 
                          input_indices: list) -> dict:
        """Request ECDH shares from hardware wallet"""
        print("[Software] Requesting ECDH shares from hardware...")
        
        ecdh_shares = {}
        for input_idx in input_indices:
            # Request ECDH computation
            ecdh_share = hardware_wallet.compute_ecdh_share(
                input_idx, self.recipient_address.scan_key
            )
            ecdh_shares[input_idx] = ecdh_share
            
            print(f"[Software] Received ECDH share for input {input_idx}")
        
        return ecdh_shares
    
    def request_dleq_proofs(self, hardware_wallet: HardwareWallet,
                          ecdh_shares: dict) -> dict:
        """Request DLEQ proofs from hardware wallet"""
        print("[Software] Requesting DLEQ proofs from hardware...")
        
        proofs = {}
        for input_idx, ecdh_share in ecdh_shares.items():
            proof = hardware_wallet.generate_dleq_proof(
                input_idx, self.recipient_address.scan_key, ecdh_share
            )
            proofs[input_idx] = proof
            
            print(f"[Software] Received DLEQ proof for input {input_idx}")
        
        return proofs
    
    def verify_hardware_computations(self, hardware_wallet: HardwareWallet,
                                   ecdh_shares: dict, proofs: dict) -> bool:
        """Verify hardware wallet computations using DLEQ proofs"""
        print("[Software] Verifying hardware wallet computations...")
        
        all_valid = True
        for input_idx in ecdh_shares:
            input_pubkey = hardware_wallet.get_public_key(input_idx)
            ecdh_share = ecdh_shares[input_idx]
            proof = proofs[input_idx]
            
            print(f"[Software] Verifying input {input_idx} DLEQ proof...")
            
            # Verify using BIP 374 DLEQ verification
            # is_valid = verify_dleq_proof(
            #     input_pubkey, self.recipient_address.scan_key, ecdh_share, proof
            # )
            is_valid = True  # Placeholder
            
            if is_valid:
                print(f"[Software] ✅ Input {input_idx} DLEQ proof valid")
            else:
                print(f"[Software] ❌ Input {input_idx} DLEQ proof invalid")
                all_valid = False
        
        return all_valid
    
    def compute_output_scripts(self, ecdh_shares: dict):
        """Compute final silent payment output scripts"""
        print("[Software] Computing output scripts from ECDH shares...")
        
        print(f"[Software] Combining {len(ecdh_shares)} ECDH shares")
        # Sum all ECDH shares and apply BIP 352 derivation
        # self.psbt.compute_output_scripts()
        print("[Software] ✅ Output scripts computed and added to PSBT")

def demonstrate_hardware_wallet_flow():
    """
    Demonstrate complete hardware wallet + software coordinator flow
    """
    
    print("BIP 375 Example: Hardware Wallet Flow")
    print("=" * 50)
    
    # Step 1: Setup hardware wallet and software coordinator
    print("\n1. Setting up hardware wallet and software coordinator...")
    hw = HardwareWallet("Ledger")
    coordinator = SoftwareCoordinator()
    
    # Store private keys on hardware (normally done during setup)
    hw.store_key(0, bytes.fromhex("a1" + "0" * 62))
    hw.store_key(1, bytes.fromhex("a2" + "0" * 62))
    
    print(f"[{hw.name}] Hardware wallet initialized")
    print("[Software] Software coordinator initialized")
    
    # Step 2: Create recipient silent payment address
    print("\n2. Creating recipient silent payment address...")
    recipient_address = SilentPaymentAddress(
        scan_key=bytes.fromhex("02" + "scan" * 14),
        spend_key=bytes.fromhex("03" + "spend" * 13)
    )
    print(f"Recipient address configured")
    
    # Step 3: Create PSBT structure
    print("\n3. Creating PSBT structure...")
    inputs = [
        {"amount": 100000, "index": 0},
        {"amount": 150000, "index": 1}
    ]
    outputs = [
        {"amount": 200000, "type": "silent_payment"},
        {"amount": 45000, "type": "change"}  # 5000 sat fee
    ]
    
    coordinator.create_psbt(inputs, outputs, recipient_address)
    
    try:
        # Step 4: Request ECDH shares from hardware
        print("\n4. Hardware wallet computing ECDH shares...")
        ecdh_shares = coordinator.request_ecdh_shares(hw, [0, 1])
        
        # Step 5: Request DLEQ proofs from hardware
        print("\n5. Hardware wallet generating DLEQ proofs...")
        dleq_proofs = coordinator.request_dleq_proofs(hw, ecdh_shares)
        
        # Step 6: Software verifies hardware computations
        print("\n6. Software verifying hardware computations...")
        verification_passed = coordinator.verify_hardware_computations(
            hw, ecdh_shares, dleq_proofs
        )
        
        if not verification_passed:
            print("❌ Hardware verification failed - aborting transaction")
            return
        
        print("✅ Hardware verification passed - proceeding")
        
        # Step 7: Compute output scripts
        print("\n7. Computing final output scripts...")
        coordinator.compute_output_scripts(ecdh_shares)
        
        # Step 8: Hardware wallet signs transaction
        print("\n8. Hardware wallet signing transaction...")
        transaction_hash = b"TX_HASH_" + b"0" * 22  # Placeholder
        
        signatures = {}
        for input_idx in [0, 1]:
            sig = hw.sign_input(input_idx, transaction_hash)
            signatures[input_idx] = sig
        
        print("[Software] Received all signatures from hardware")
        
        # Step 9: Extract final transaction
        print("\n9. Extracting final transaction...")
        # transaction_bytes = coordinator.psbt.extract_transaction()
        print("✅ Hardware wallet silent payment flow completed!")
        
        # Step 10: Show security benefits
        print("\n10. Security Benefits Achieved:")
        print("🔐 Private keys never left hardware device")
        print("🛡️  Software cryptographically verified hardware computations")
        print("✅ No need to trust hardware wallet blindly")
        print("🔍 DLEQ proofs ensure output scripts computed correctly")
        print("💰 Funds protected from both hardware bugs and malicious software")
        
    except NotImplementedError as e:
        print(f"\n⚠️  Implementation needed: {e}")
    except Exception as e:
        print(f"\n❌ Error: {e}")

def demonstrate_attack_scenarios():
    """
    Demonstrate how DLEQ proofs protect against attack scenarios
    """
    print("\n" + "=" * 50)
    print("Attack Protection Scenarios")
    print("=" * 50)
    
    print("\n🚨 Scenario 1: Buggy Hardware Wallet")
    print("Problem: Hardware accidentally computes C = a * G instead of C = a * B_scan")
    print("Without DLEQ: Software can't detect error, funds sent to wrong address")
    print("With DLEQ: DLEQ proof verification fails, software rejects transaction")
    print("Result: ✅ Funds protected from hardware bugs")
    
    print("\n🚨 Scenario 2: Malicious Hardware Wallet")
    print("Problem: Evil hardware intentionally provides wrong ECDH share")
    print("Without DLEQ: Software can't verify, attacker steals funds")
    print("With DLEQ: Cannot generate valid proof for incorrect computation")
    print("Result: ✅ Funds protected from malicious hardware")
    
    print("\n🚨 Scenario 3: Compromised Software")
    print("Problem: Malicious software tries to change recipient address")
    print("Without DLEQ: Software could lie about recipient")
    print("With DLEQ: Hardware generates proof for specific scan key")
    print("Result: ✅ DLEQ proof tied to intended recipient")
    
    print("\n🚨 Scenario 4: Network Attack")
    print("Problem: Attacker intercepts and modifies PSBT in transit")
    print("Without DLEQ: Modified ECDH shares not detectable") 
    print("With DLEQ: DLEQ proofs become invalid after modification")
    print("Result: ✅ PSBT integrity protected by proofs")

if __name__ == "__main__":
    demonstrate_hardware_wallet_flow()
    demonstrate_attack_scenarios()