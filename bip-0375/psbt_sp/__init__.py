#!/usr/bin/env python3
"""
PSBT Silent Payment (psbt_sp) Package

Clean Python package for BIP 375 - Sending Silent Payments with PSBTs
Provides PSBT v2 implementation with silent payment extensions.
"""

# Core PSBT functionality
from .psbt import SilentPaymentPSBT, SilentPaymentAddress, ECDHShare, validate_psbt_silent_payments

# Cryptographic utilities  
from .crypto import Wallet

# Serialization utilities (for advanced usage)
from .serialization import PSBTField, PSBTv2, compact_size_uint, create_witness_utxo

__version__ = "1.0.0"
__author__ = "BIP 375 Implementation"
__description__ = "PSBT v2 with BIP 375 Silent Payment extensions"

# Public API - what gets imported with "from psbt_sp import *"
__all__ = [
    # Core classes
    "SilentPaymentPSBT",
    "SilentPaymentAddress", 
    "ECDHShare",
    "Wallet",
    
    # Serialization classes (for advanced usage)
    "PSBTField",
    "PSBTv2",
    
    # Utility functions
    "compact_size_uint",
    "create_witness_utxo",
    
    # Package metadata
    "__version__",
    "__author__", 
    "__description__"
]