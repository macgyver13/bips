#!/usr/bin/env python3
"""
Complete BIP 375 Test Vector Generator

Implements all test scenarios from test_vectors.json with full PSBT structures
that properly trigger validation rules. Creates both invalid and valid PSBTs
with complete cryptographic material for full DLEQ validation.
"""

import json
import hashlib
import struct
import base64
import sys
import os
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dleq_374 import dleq_generate_proof, dleq_verify_proof
from psbt_sp.crypto import Wallet
from psbt_sp.serialization import create_witness_utxo
from psbt_sp.psbt import SilentPaymentPSBT
from psbt_sp.constants import PSBTFieldType

@dataclass
class GenInputKey:
    """Complete key material for a PSBT input with all necessary fields"""
    input_index: int
    private_key: str  # 32 bytes hex
    public_key: str   # 33 bytes hex (compressed)
    prevout_txid: str # 32 bytes hex (txid)
    prevout_index: int
    prevout_scriptpubkey: str  # hex
    amount: int
    witness_utxo: Optional[str] = None  # hex serialized witness utxo
    sequence: int = 0xffffffff
    
@dataclass  
class GenScanKey:
    """Complete silent payment scan/spend key pair with metadata"""
    scan_pubkey: str    # 33 bytes hex (compressed)
    spend_pubkey: str   # 33 bytes hex (compressed) 
    label: Optional[int] = None
    
@dataclass
class GenECDHShare:
    """Complete ECDH computation result with validation data"""
    scan_key: str      # 33 bytes hex (compressed)
    ecdh_result: str   # 33 bytes hex (compressed)
    dleq_proof: Optional[str] = None  # 64 bytes hex
    is_global: bool = False  # True if global ECDH share, False if per-input
    input_index: Optional[int] = None  # For per-input shares
    
@dataclass
class GenOutput:
    """Complete output specification"""
    output_index: int
    amount: int
    script: str  # hex
    is_silent_payment: bool
    sp_info: Optional[str] = None  # PSBT_OUT_SP_V0_INFO hex data
    sp_label: Optional[int] = None  # PSBT_OUT_SP_V0_LABEL

@dataclass
class GenTestVector:
    """Complete test vector with all cryptographic material and validation data"""
    description: str
    psbt: str  # base64
    input_keys: List[GenInputKey]
    scan_keys: List[GenScanKey]
    expected_ecdh_shares: List[GenECDHShare]
    expected_outputs: List[GenOutput]
    comment: str  # Additional context for both valid and invalid cases

class TestVectorGenerator:
    """Generates complete BIP 375 test vectors for all scenarios"""
    
    def __init__(self, seed: str = "bip375_complete_seed"):
        """Initialize with deterministic seed for reproducible results"""
        self.wallet = Wallet(seed)
        self.test_vectors = {
            "description": "BIP 375 Test Vectors - All Scenarios",
            "version": "1.0",
            "format_notes": [
                "All keys are hex-encoded",
                "PSBTs have all necessary fields",
                "Test vectors are organized into 'invalid' and 'valid' arrays",
                "Comment provides additional context for all test cases"
            ],
            "invalid": [],
            "valid": []
        }
    
    def create_complete_psbt_base(self, num_inputs: int, num_outputs: int) -> SilentPaymentPSBT:
        """Create a complete PSBT v2 base structure"""
        psbt = SilentPaymentPSBT()

        # Add required global fields for PSBT v2
        psbt.add_global_field(PSBTFieldType.PSBT_GLOBAL_VERSION, b'', struct.pack('<I', 2))  # PSBT format version
        psbt.add_global_field(PSBTFieldType.PSBT_GLOBAL_TX_VERSION , b'', struct.pack('<I', 2))  # 4 bytes for tx version
        psbt.add_global_field(PSBTFieldType.PSBT_GLOBAL_INPUT_COUNT, b'', struct.pack('<I', num_inputs))
        psbt.add_global_field(PSBTFieldType.PSBT_GLOBAL_OUTPUT_COUNT, b'', struct.pack('<I', num_outputs))
        psbt.add_global_field(PSBTFieldType.PSBT_GLOBAL_TX_MODIFIABLE, b'', b'\x03')  # Allow input/output modification

        return psbt

    def add_base_input_fields(self, psbt: SilentPaymentPSBT, input_index: int,
                              prevout_txid: bytes, prevout_index: int,
                              witness_utxo: bytes, sequence: int = 0xfffffffe):
        """Add required PSBTv2 input fields"""
        # Required PSBTv2 fields
        psbt.add_input_field(input_index, PSBTFieldType.PSBT_IN_PREVIOUS_TXID, b'', prevout_txid)
        psbt.add_input_field(input_index, PSBTFieldType.PSBT_IN_OUTPUT_INDEX, b'', struct.pack('<I', prevout_index))
        psbt.add_input_field(input_index, PSBTFieldType.PSBT_IN_WITNESS_UTXO, b'', witness_utxo)
        psbt.add_input_field(input_index, PSBTFieldType.PSBT_IN_SEQUENCE, b'', struct.pack('<I', sequence))

    # Invalid Test Case Generators
    def generate_missing_dleq_test(self) -> GenTestVector:
        """Missing DLEQ proof for ECDH share"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share
        ecdh_result = input_priv * scan_pub
        psbt = self.create_complete_psbt_base(1, 1)

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_0".encode()).digest()
        witness_script = bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]  # P2WPKH
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(psbt, 0, prevout_txid, 0, witness_utxo)

        # Add ECDH share WITHOUT DLEQ proof (this should trigger error)
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SP_ECDH_SHARE, scan_pub.bytes, ecdh_result.to_bytes_compressed())
        # Deliberately omit PSBT_IN_SP_DLEQ (0x1e)

        # Add silent payment output to trigger validation
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 95000))
        output_script = bytes([0x51, 0x20]) + hashlib.sha256(b"silent_payment_script").digest()  # P2TR
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SCRIPT, b'', output_script)
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SP_V0_INFO, b'', scan_pub.bytes + spend_pub.bytes)

        return GenTestVector(
            description="Missing DLEQ proof for ECDH share",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[GenInputKey(
                input_index=0,
                private_key=input_priv.hex,
                public_key=input_pub.hex,
                prevout_txid=prevout_txid.hex(),
                prevout_index=0,
                prevout_scriptpubkey=witness_script.hex(),
                amount=100000,
                witness_utxo=witness_utxo.hex()
            )],
            scan_keys=[GenScanKey(
                scan_pubkey=scan_pub.hex,
                spend_pubkey=spend_pub.hex
            )],
            expected_ecdh_shares=[GenECDHShare(
                scan_key=scan_pub.hex,
                ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                dleq_proof=None,  # Missing!
                is_global=False,
                input_index=0
            )],
            expected_outputs=[GenOutput(
                output_index=0,
                amount=95000,
                script=output_script.hex(),
                is_silent_payment=True,
                sp_info=(scan_pub.bytes + spend_pub.bytes).hex()
            )],
            comment="PSBT_IN_SP_ECDH_SHARE without corresponding PSBT_IN_SP_DLEQ"
        )
    
    def generate_invalid_dleq_test(self) -> GenTestVector:
        """Invalid DLEQ proof"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share
        ecdh_result = input_priv * scan_pub

        # Generate COMPLETELY invalid proof by using wrong private key
        wrong_input_priv, _ = self.wallet.create_key_pair("wrong_input", 1)

        # Generate proof with wrong private key - this should be invalid
        invalid_proof = dleq_generate_proof(wrong_input_priv, scan_pub, Wallet.random_bytes())

        # Verify the proof is actually invalid when checked against the real input key
        assert not dleq_verify_proof(input_pub, scan_pub, ecdh_result, invalid_proof), "Generated proof should be invalid but isn't"

        psbt = self.create_complete_psbt_base(1, 1)

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_1".encode()).digest()
        witness_script = bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(psbt, 0, prevout_txid, 0, witness_utxo)

        # Add ECDH share WITH INVALID DLEQ proof
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SP_ECDH_SHARE, scan_pub.bytes, ecdh_result.to_bytes_compressed())
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SP_DLEQ, scan_pub.bytes, invalid_proof) # (invalid)

        # Add silent payment output
        sp_info = scan_pub.bytes + spend_pub.bytes
        output_script = bytes([0x51, 0x20]) + hashlib.sha256(b"silent_payment_script_1").digest()

        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 95000))
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SCRIPT, b'', output_script)
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info)

        return GenTestVector(
            description="Invalid DLEQ proof",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[GenInputKey(
                input_index=0,
                private_key=input_priv.hex,
                public_key=input_pub.hex,
                prevout_txid=prevout_txid.hex(),
                prevout_index=0,
                prevout_scriptpubkey=witness_script.hex(),
                amount=100000,
                witness_utxo=witness_utxo.hex()
            )],
            scan_keys=[GenScanKey(
                scan_pubkey=scan_pub.hex,
                spend_pubkey=spend_pub.hex
            )],
            expected_ecdh_shares=[GenECDHShare(
                scan_key=scan_pub.hex,
                ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                dleq_proof=invalid_proof.hex(),
                is_global=False,
                input_index=0
            )],
            expected_outputs=[GenOutput(
                output_index=0,
                amount=95000,
                script=output_script.hex(),
                is_silent_payment=True,
                sp_info=sp_info.hex()
            )],
            comment="DLEQ proof verification failed"
        )
    
    def generate_non_sighash_all_test(self) -> GenTestVector:
        """Non-SIGHASH_ALL signature with silent payments"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share with valid proof
        ecdh_result = input_priv * scan_pub
        valid_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes(5))

        psbt = self.create_complete_psbt_base(1, 1)

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_2".encode()).digest()
        witness_script = bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(psbt, 0, prevout_txid, 0, witness_utxo)

        # Add NON-SIGHASH_ALL signature type (this should trigger error)
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SIGHASH_TYPE, b'', struct.pack('<I', 0x02))  # SIGHASH_NONE

        # Add valid ECDH share and proof
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SP_ECDH_SHARE, scan_pub.bytes, ecdh_result.to_bytes_compressed())
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SP_DLEQ, scan_pub.bytes, valid_proof)

        # Add silent payment output
        sp_info = scan_pub.bytes + spend_pub.bytes
        output_script = bytes([0x51, 0x20]) + hashlib.sha256(b"silent_payment_script_2").digest()

        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 95000))
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SCRIPT, b'', output_script)
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info)

        return GenTestVector(
            description="Non-SIGHASH_ALL signature with silent payments",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[GenInputKey(
                input_index=0,
                private_key=input_priv.hex,
                public_key=input_pub.hex,
                prevout_txid=prevout_txid.hex(),
                prevout_index=0,
                prevout_scriptpubkey=witness_script.hex(),
                amount=100000,
                witness_utxo=witness_utxo.hex()
            )],
            scan_keys=[GenScanKey(
                scan_pubkey=scan_pub.hex,
                spend_pubkey=spend_pub.hex
            )],
            expected_ecdh_shares=[GenECDHShare(
                scan_key=scan_pub.hex,
                ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                dleq_proof=valid_proof.hex(),
                is_global=False,
                input_index=0
            )],
            expected_outputs=[GenOutput(
                output_index=0,
                amount=95000,
                script=output_script.hex(),
                is_silent_payment=True,
                sp_info=sp_info.hex()
            )],
            comment="Silent payment outputs require SIGHASH_ALL signatures only"
        )
    
    def generate_mixed_segwit_test(self) -> GenTestVector:
        """Mixed segwit versions with silent payments"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share with valid proof
        ecdh_result = input_priv * scan_pub
        valid_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes())

        psbt = self.create_complete_psbt_base(1, 1)

        # Add complete input fields with HYPOTHETICAL segwit v2 (OP_2 = 0x52)
        # NOTE: Segwit v2 does NOT exist in Bitcoin (only v0 and v1/Taproot are defined)
        # This tests that BIP 375 validation correctly rejects undefined future versions
        prevout_txid = hashlib.sha256("prevout_3".encode()).digest()
        witness_script = bytes([0x52, 0x20]) + hashlib.sha256(b"segwit_v2_script").digest()  # Hypothetical Segwit v2
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(psbt, 0, prevout_txid, 0, witness_utxo)
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SIGHASH_TYPE, b'', struct.pack('<I', 0x01))  # SIGHASH_ALL

        # Add valid ECDH share and proof
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SP_ECDH_SHARE, scan_pub.bytes, ecdh_result.to_bytes_compressed())
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SP_DLEQ, scan_pub.bytes, valid_proof)

        # Add silent payment output
        sp_info = scan_pub.bytes + spend_pub.bytes
        output_script = bytes([0x51, 0x20]) + hashlib.sha256(b"silent_payment_script_3").digest()

        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 95000))
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SCRIPT, b'', output_script)
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info)

        return GenTestVector(
            description="Mixed segwit versions with silent payments",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[GenInputKey(
                input_index=0,
                private_key=input_priv.hex,
                public_key=input_pub.hex,
                prevout_txid=prevout_txid.hex(),
                prevout_index=0,
                prevout_scriptpubkey=witness_script.hex(),
                amount=100000,
                witness_utxo=witness_utxo.hex()
            )],
            scan_keys=[GenScanKey(
                scan_pubkey=scan_pub.hex,
                spend_pubkey=spend_pub.hex
            )],
            expected_ecdh_shares=[GenECDHShare(
                scan_key=scan_pub.hex,
                ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                dleq_proof=valid_proof.hex(),
                is_global=False,
                input_index=0
            )],
            expected_outputs=[GenOutput(
                output_index=0,
                amount=95000,
                script=output_script.hex(),
                is_silent_payment=True,
                sp_info=sp_info.hex()
            )],
            comment="mixed_segwit"
        )
    
    def generate_no_ecdh_shares_test(self) -> GenTestVector:
        """Silent payment outputs but no ECDH shares"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        psbt = self.create_complete_psbt_base(1, 1)

        # Add complete input fields (no ECDH shares)
        prevout_txid = hashlib.sha256("prevout_4".encode()).digest()
        witness_script = bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(psbt, 0, prevout_txid, 0, witness_utxo)
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SIGHASH_TYPE, b'', struct.pack('<I', 0x01))  # SIGHASH_ALL

        # Add silent payment output WITHOUT any ECDH shares (should trigger error)
        sp_info = scan_pub.bytes + spend_pub.bytes
        output_script = bytes([0x51, 0x20]) + hashlib.sha256(b"silent_payment_script_4").digest()

        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 95000))
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SCRIPT, b'', output_script)
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info)

        return GenTestVector(
            description="Silent payment outputs but no ECDH shares",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[GenInputKey(
                input_index=0,
                private_key=input_priv.hex,
                public_key=input_pub.hex,
                prevout_txid=prevout_txid.hex(),
                prevout_index=0,
                prevout_scriptpubkey=witness_script.hex(),
                amount=100000,
                witness_utxo=witness_utxo.hex()
            )],
            scan_keys=[GenScanKey(
                scan_pubkey=scan_pub.hex,
                spend_pubkey=spend_pub.hex
            )],
            expected_ecdh_shares=[],  # No ECDH shares!
            expected_outputs=[GenOutput(
                output_index=0,
                amount=95000,
                script=output_script.hex(),
                is_silent_payment=True,
                sp_info=sp_info.hex()
            )],
            comment="no_ecdh_shares"
        )
    
    def generate_missing_global_dleq_test(self) -> GenTestVector:
        """Global ECDH share without DLEQ proof"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share
        ecdh_result = input_priv * scan_pub
        psbt = self.create_complete_psbt_base(1, 1)

        # Add global ECDH share WITHOUT DLEQ proof
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SP_ECDH_SHARE, scan_pub.bytes, ecdh_result.to_bytes_compressed())
        # Deliberately omit PSBT_GLOBAL_SP_DLEQ (0x08)

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_5".encode()).digest()
        witness_script = bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(psbt, 0, prevout_txid, 0, witness_utxo)
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SIGHASH_TYPE, b'', struct.pack('<I', 0x01))  # SIGHASH_ALL

        # Add silent payment output
        sp_info = scan_pub.bytes + spend_pub.bytes
        output_script = bytes([0x51, 0x20]) + hashlib.sha256(b"silent_payment_script_5").digest()

        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 95000))
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SCRIPT, b'', output_script)
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info)

        return GenTestVector(
            description="Global ECDH share without DLEQ proof",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[GenInputKey(
                input_index=0,
                private_key=input_priv.hex,
                public_key=input_pub.hex,
                prevout_txid=prevout_txid.hex(),
                prevout_index=0,
                prevout_scriptpubkey=witness_script.hex(),
                amount=100000,
                witness_utxo=witness_utxo.hex()
            )],
            scan_keys=[GenScanKey(
                scan_pubkey=scan_pub.hex,
                spend_pubkey=spend_pub.hex
            )],
            expected_ecdh_shares=[GenECDHShare(
                scan_key=scan_pub.hex,
                ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                dleq_proof=None,  # Missing!
                is_global=True
            )],
            expected_outputs=[GenOutput(
                output_index=0,
                amount=95000,
                script=output_script.hex(),
                is_silent_payment=True,
                sp_info=sp_info.hex()
            )],
            comment="missing_global_dleq"
        )
    
    def generate_wrong_sp_info_size_test(self) -> GenTestVector:
        """Wrong SP_V0_INFO field size"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share with valid proof
        ecdh_result = input_priv * scan_pub
        valid_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes())

        psbt = self.create_complete_psbt_base(1, 1)

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_6".encode()).digest()
        witness_script = bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(psbt, 0, prevout_txid, 0, witness_utxo)
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SIGHASH_TYPE, b'', struct.pack('<I', 0x01))  # SIGHASH_ALL

        # Add valid ECDH share and proof
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SP_ECDH_SHARE, scan_pub.bytes, ecdh_result.to_bytes_compressed())
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SP_DLEQ, scan_pub.bytes, valid_proof)

        # Add silent payment output with WRONG SIZE SP_V0_INFO (should be 66 bytes)
        wrong_sp_info = scan_pub.bytes + spend_pub.bytes[:32]  # Only 65 bytes
        output_script = bytes([0x51, 0x20]) + hashlib.sha256(b"silent_payment_script_6").digest()

        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 95000))
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SCRIPT, b'', output_script)
        psbt.add_output_field(0, 0x09, b'', wrong_sp_info)  # PSBT_OUT_SP_V0_INFO (wrong size!)

        return GenTestVector(
            description="Wrong SP_V0_INFO field size",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[GenInputKey(
                input_index=0,
                private_key=input_priv.hex,
                public_key=input_pub.hex,
                prevout_txid=prevout_txid.hex(),
                prevout_index=0,
                prevout_scriptpubkey=witness_script.hex(),
                amount=100000,
                witness_utxo=witness_utxo.hex()
            )],
            scan_keys=[GenScanKey(
                scan_pubkey=scan_pub.hex,
                spend_pubkey=spend_pub.hex
            )],
            expected_ecdh_shares=[GenECDHShare(
                scan_key=scan_pub.hex,
                ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                dleq_proof=valid_proof.hex(),
                is_global=False,
                input_index=0
            )],
            expected_outputs=[GenOutput(
                output_index=0,
                amount=95000,
                script=output_script.hex(),
                is_silent_payment=True,
                sp_info=wrong_sp_info.hex()  # Wrong size!
            )],
            comment="wrong_sp_info_size"
        )
    
    # Valid Test Case Generators
    
    def generate_single_signer_global_test(self) -> GenTestVector:
        """Single signer with global ECDH share"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub

        # Compute ECDH share with valid proof
        ecdh_result = input_priv * scan_pub
        valid_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes())

        # Verify proof is valid
        assert dleq_verify_proof(input_pub, scan_pub, ecdh_result, valid_proof)

        psbt = self.create_complete_psbt_base(1, 1)

        # Add global ECDH share (not per-input)
        psbt.add_global_field(PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE, scan_pub.bytes, ecdh_result.to_bytes_compressed())
        psbt.add_global_field(PSBTFieldType.PSBT_GLOBAL_SP_DLEQ, scan_pub.bytes, valid_proof)

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_10".encode()).digest()
        witness_script = bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(psbt, 0, prevout_txid, 0, witness_utxo)
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SIGHASH_TYPE, b'', struct.pack('<I', 0x01))  # SIGHASH_ALL

        # Add silent payment output with computed script
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 95000))
        output_script = bytes([0x51, 0x20]) + hashlib.sha256(b"computed_silent_payment_script").digest()
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SCRIPT, b'', output_script)
        sp_info = scan_pub.bytes + spend_pub.bytes
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info)

        return GenTestVector(
            description="Single signer with global ECDH share",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[GenInputKey(
                input_index=0,
                private_key=input_priv.hex,
                public_key=input_pub.hex,
                prevout_txid=prevout_txid.hex(),
                prevout_index=0,
                prevout_scriptpubkey=witness_script.hex(),
                amount=100000,
                witness_utxo=witness_utxo.hex()
            )],
            scan_keys=[GenScanKey(
                scan_pubkey=scan_pub.hex,
                spend_pubkey=spend_pub.hex
            )],
            expected_ecdh_shares=[GenECDHShare(
                scan_key=scan_pub.hex,
                ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                dleq_proof=valid_proof.hex(),
                is_global=True
            )],
            expected_outputs=[GenOutput(
                output_index=0,
                amount=95000,
                script=output_script.hex(),
                is_silent_payment=True,
                sp_info=sp_info.hex()
            )],
            comment="One entity controls all inputs, uses global approach for efficiency"
        )
    
    def generate_multi_party_per_input_test(self) -> GenTestVector:
        """Multi-party with per-input ECDH shares"""
        # Use local wallet keys
        input1_priv, input1_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub
        # Two different inputs with different signers
        input2_priv, input2_pub = self.wallet.input_key_pair(1)
        
        # Compute ECDH shares for both inputs
        ecdh_result1 = input1_priv * scan_pub
        ecdh_result2 = input2_priv * scan_pub
        
        # Generate valid proofs for both
        valid_proof1 = dleq_generate_proof(input1_priv, scan_pub, Wallet.random_bytes())
        valid_proof2 = dleq_generate_proof(input2_priv, scan_pub, Wallet.random_bytes())
        
        psbt = self.create_complete_psbt_base(2, 1)
        
        # Add per-input ECDH shares and proofs
        for i, (ecdh_result, valid_proof, input_pub, prevout_name) in enumerate([
            (ecdh_result1, valid_proof1, input1_pub, "prevout_11"),
            (ecdh_result2, valid_proof2, input2_pub, "prevout_12")
        ]):
            # Add complete input fields
            prevout_txid = hashlib.sha256(prevout_name.encode()).digest()
            witness_script = bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
            witness_utxo = create_witness_utxo(50000, witness_script)

            self.add_base_input_fields(psbt, i, prevout_txid, 0, witness_utxo)
            psbt.add_input_field(i, PSBTFieldType.PSBT_IN_SIGHASH_TYPE, b'', struct.pack('<I', 0x01))  # SIGHASH_ALL

            # Add per-input ECDH share and DLEQ proof
            psbt.add_input_field(i, PSBTFieldType.PSBT_IN_SP_ECDH_SHARE, scan_pub.bytes, ecdh_result.to_bytes_compressed())
            psbt.add_input_field(i, PSBTFieldType.PSBT_IN_SP_DLEQ, scan_pub.bytes, valid_proof)
        
        # Add silent payment output
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 95000))
        output_script = bytes([0x51, 0x20]) + hashlib.sha256(b"multi_party_silent_payment").digest()
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SCRIPT, b'', output_script)
        sp_info = scan_pub.bytes + spend_pub.bytes
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info)
        
        return GenTestVector(
            description="Multi-party with per-input ECDH shares",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[
                GenInputKey(
                    input_index=0,
                    private_key=input1_priv.to_bytes(32, 'big').hex(),
                    public_key=input1_pub.to_bytes_compressed().hex(),
                    prevout_txid=hashlib.sha256("prevout_11".encode()).digest().hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=(bytes([0x00, 0x14]) + hashlib.sha256(input1_pub.to_bytes_compressed()).digest()[:20]).hex(),
                    amount=50000,
                    witness_utxo=create_witness_utxo(50000, bytes([0x00, 0x14]) + hashlib.sha256(input1_pub.to_bytes_compressed()).digest()[:20]).hex()
                ),
                GenInputKey(
                    input_index=1,
                    private_key=input2_priv.to_bytes(32, 'big').hex(),
                    public_key=input2_pub.to_bytes_compressed().hex(),
                    prevout_txid=hashlib.sha256("prevout_12".encode()).digest().hex(),
                    prevout_index=0,
                    prevout_scriptpubkey=(bytes([0x00, 0x14]) + hashlib.sha256(input2_pub.to_bytes_compressed()).digest()[:20]).hex(),
                    amount=50000,
                    witness_utxo=create_witness_utxo(50000, bytes([0x00, 0x14]) + hashlib.sha256(input2_pub.to_bytes_compressed()).digest()[:20]).hex()
                )
            ],
            scan_keys=[GenScanKey(
                scan_pubkey=scan_pub.hex,
                spend_pubkey=spend_pub.hex
            )],
            expected_ecdh_shares=[
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result1.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof1.hex(),
                    is_global=False,
                    input_index=0
                ),
                GenECDHShare(
                    scan_key=scan_pub.hex,
                    ecdh_result=ecdh_result2.to_bytes_compressed().hex(),
                    dleq_proof=valid_proof2.hex(),
                    is_global=False,
                    input_index=1
                )
            ],
            expected_outputs=[GenOutput(
                output_index=0,
                amount=95000,
                script=output_script.hex(),
                is_silent_payment=True,
                sp_info=sp_info.hex()
            )],
            comment="Two signers each contribute ECDH shares for their respective inputs"
        )
    
    def generate_silent_payment_with_change_test(self) -> GenTestVector:
        """Silent payment with change detection"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub
        
        # Compute ECDH share with valid proof
        ecdh_result = input_priv * scan_pub
        valid_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes())
        
        psbt = self.create_complete_psbt_base(1, 2)  # 1 input, 2 outputs

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_13".encode()).digest()
        witness_script = bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(psbt, 0, prevout_txid, 0, witness_utxo)
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SIGHASH_TYPE, b'', struct.pack('<I', 0x01))  # SIGHASH_ALL

        # Add global ECDH share and DLEQ proof
        psbt.add_global_field(PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE, scan_pub.bytes, ecdh_result.to_bytes_compressed())
        psbt.add_global_field(PSBTFieldType.PSBT_GLOBAL_SP_DLEQ, scan_pub.bytes, valid_proof)

        # Add silent payment output with label
        sp_info = scan_pub.bytes + spend_pub.bytes
        sp_output_script = bytes([0x51, 0x20]) + hashlib.sha256(b"silent_payment_with_change").digest()
        label_value = struct.pack('<I', 1)  # Label = 1
        
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 50000))
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SCRIPT, b'', sp_output_script)
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info)
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SP_V0_LABEL, b'', label_value)
        
        # Add change output with BIP32 derivation
        change_script = bytes([0x00, 0x14]) + hashlib.sha256(b"change_script").digest()[:20]  # P2WPKH
        bip32_derivation = input_pub.bytes + b'\x04' + struct.pack('>I', 0) + struct.pack('>I', 1)  # m/0/1
        
        psbt.add_output_field(1, PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 45000))  # Change
        psbt.add_output_field(1, PSBTFieldType.PSBT_OUT_SCRIPT, b'', change_script)
        psbt.add_output_field(1, PSBTFieldType.PSBT_OUT_BIP32_DERIVATION, input_pub.bytes, bip32_derivation[33:])  # Key as key, derivation as value
        
        return GenTestVector(
            description="Silent payment with change detection",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[GenInputKey(
                input_index=0,
                private_key=input_priv.hex,
                public_key=input_pub.hex,
                prevout_txid=prevout_txid.hex(),
                prevout_index=0,
                prevout_scriptpubkey=witness_script.hex(),
                amount=100000,
                witness_utxo=witness_utxo.hex()
            )],
            scan_keys=[GenScanKey(
                scan_pubkey=scan_pub.hex,
                spend_pubkey=spend_pub.hex,
                label=1
            )],
            expected_ecdh_shares=[GenECDHShare(
                scan_key=scan_pub.hex,
                ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                dleq_proof=valid_proof.hex(),
                is_global=False,
                input_index=0
            )],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=50000,
                    script=sp_output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex(),
                    sp_label=1
                ),
                GenOutput(
                    output_index=1,
                    amount=45000,
                    script=change_script.hex(),
                    is_silent_payment=False
                )
            ],
            comment="Uses PSBT_OUT_SP_V0_LABEL and BIP32 derivation for change identification"
        )
    
    def generate_multiple_silent_payment_outputs_test(self) -> GenTestVector:
        """Multiple silent payment outputs to same scan key"""
        # Use local wallet keys
        input_priv, input_pub = self.wallet.input_key_pair(0)
        scan_pub = self.wallet.scan_pub
        spend_pub = self.wallet.spend_pub
        
        # Compute ECDH share with valid proof
        ecdh_result = input_priv * scan_pub
        valid_proof = dleq_generate_proof(input_priv, scan_pub, Wallet.random_bytes())
        
        psbt = self.create_complete_psbt_base(1, 2)  # 1 input, 2 outputs

        # Add complete input fields
        prevout_txid = hashlib.sha256("prevout_14".encode()).digest()
        witness_script = bytes([0x00, 0x14]) + hashlib.sha256(input_pub.bytes).digest()[:20]
        witness_utxo = create_witness_utxo(100000, witness_script)

        self.add_base_input_fields(psbt, 0, prevout_txid, 0, witness_utxo)
        psbt.add_input_field(0, PSBTFieldType.PSBT_IN_SIGHASH_TYPE, b'', struct.pack('<I', 0x01))  # SIGHASH_ALL

        # Add global ECDH share and DLEQ proof
        psbt.add_global_field(PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE, scan_pub.bytes, ecdh_result.to_bytes_compressed())
        psbt.add_global_field(PSBTFieldType.PSBT_GLOBAL_SP_DLEQ, scan_pub.bytes, valid_proof)
        
        # Add first silent payment output
        sp_info = scan_pub.bytes + spend_pub.bytes
        sp1_output_script = bytes([0x51, 0x20]) + hashlib.sha256(b"silent_payment_output_1").digest()
        
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 40000))
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SCRIPT, b'', sp1_output_script)
        psbt.add_output_field(0, PSBTFieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info)
        
        # Add second silent payment output to same scan key (different k value)
        sp2_output_script = bytes([0x51, 0x20]) + hashlib.sha256(b"silent_payment_output_2").digest()
        
        psbt.add_output_field(1, PSBTFieldType.PSBT_OUT_AMOUNT, b'', struct.pack('<Q', 55000))
        psbt.add_output_field(1, PSBTFieldType.PSBT_OUT_SCRIPT, b'', sp2_output_script)
        psbt.add_output_field(1, PSBTFieldType.PSBT_OUT_SP_V0_INFO, b'', sp_info)
        
        return GenTestVector(
            description="Multiple silent payment outputs to same scan key",
            psbt=base64.b64encode(psbt.serialize()).decode(),
            input_keys=[GenInputKey(
                input_index=0,
                private_key=input_priv.hex,
                public_key=input_pub.hex,
                prevout_txid=prevout_txid.hex(),
                prevout_index=0,
                prevout_scriptpubkey=witness_script.hex(),
                amount=100000,
                witness_utxo=witness_utxo.hex()
            )],
            scan_keys=[GenScanKey(
                scan_pubkey=scan_pub.hex,
                spend_pubkey=spend_pub.hex
            )],
            expected_ecdh_shares=[GenECDHShare(
                scan_key=scan_pub.hex,
                ecdh_result=ecdh_result.to_bytes_compressed().hex(),
                dleq_proof=valid_proof.hex(),
                is_global=False,
                input_index=0
            )],
            expected_outputs=[
                GenOutput(
                    output_index=0,
                    amount=40000,
                    script=sp1_output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex()
                ),
                GenOutput(
                    output_index=1,
                    amount=55000,
                    script=sp2_output_script.hex(),
                    is_silent_payment=True,
                    sp_info=sp_info.hex()
                )
            ],
            comment="Two outputs to same silent payment address, different k values"
        )
    
    def generate_all_test_vectors(self) -> Dict:
        """Generate all test vectors with complete PSBT structures"""
        
        # Invalid cases
        invalid_vectors = [
            asdict(self.generate_missing_dleq_test()),
            asdict(self.generate_invalid_dleq_test()),
            asdict(self.generate_non_sighash_all_test()),
            asdict(self.generate_mixed_segwit_test()),
            asdict(self.generate_no_ecdh_shares_test()),
            asdict(self.generate_missing_global_dleq_test()),
            asdict(self.generate_wrong_sp_info_size_test())
        ]
        
        # Valid cases  
        valid_vectors = [
            asdict(self.generate_single_signer_global_test()),
            asdict(self.generate_multi_party_per_input_test()),
            asdict(self.generate_silent_payment_with_change_test()),
            asdict(self.generate_multiple_silent_payment_outputs_test())
        ]
        
        self.test_vectors["invalid"] = invalid_vectors
        self.test_vectors["valid"] = valid_vectors
        
        return self.test_vectors
    
    def save_test_vectors(self, filename: str = "test_vectors.json"):
        """Save complete test vectors to file"""
        vectors = self.generate_all_test_vectors()
        with open(filename, 'w') as f:
            json.dump(vectors, f, indent=2)
        print(f"Complete test vectors saved to {filename}")
        print(f"Generated {len(vectors['invalid'])} invalid and {len(vectors['valid'])} valid test cases")
        return vectors

if __name__ == "__main__":
    from pathlib import Path

    # Default: save to parent directory (bip-0375 root)
    default_output = Path(__file__).parent.parent / "test_vectors.json"

    generator = TestVectorGenerator()
    generator.save_test_vectors(str(default_output))