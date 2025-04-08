"""Tests for Phase 0 components of Commit-Reveal².

Tests cover:
- Cryptographic utilities (hashing, keys, signatures)
- Participant commitment generation and verification
- Leader communication simulation
"""

import pytest
from src.crypto_utils import (
    hash_function,
    generate_secret,
    generate_keypair,
    sign_message,
    verify_signature,
    get_address
)
from src.participant import Participant

def test_hash_function():
    """Test Keccak-256 hash function."""
    data = b"test data"
    hash1 = hash_function(data)
    hash2 = hash_function(data)
    
    assert len(hash1) == 32  # 256 bits = 32 bytes
    assert hash1 == hash2    # Deterministic
    assert hash_function(b"different") != hash1  # Different input -> different hash

def test_generate_secret():
    """Test secret generation."""
    secret1 = generate_secret()
    secret2 = generate_secret()
    
    assert len(secret1) == 32
    assert secret1 != secret2  # Random

def test_keypair_generation():
    """Test ECDSA keypair generation and address derivation."""
    sk, vk = generate_keypair()
    address = get_address(vk)
    
    assert sk is not None
    assert vk is not None
    assert len(address) == 20  # Ethereum-style address

def test_signature_verification():
    """Test message signing and verification."""
    sk, vk = generate_keypair()
    message = b"test message"
    signature = sign_message(sk, message)
    
    assert verify_signature(vk, message, signature)
    assert not verify_signature(vk, b"wrong message", signature)

def test_participant_initialization():
    """Test participant initialization."""
    p = Participant("test_participant")
    
    assert p.id == "test_participant"
    assert p.sk is not None
    assert p.vk is not None
    assert len(p.address) == 20

def test_commitment_generation():
    """Test commitment chain generation and verification."""
    p = Participant("test_participant")
    p.generate_commitments()
    
    # Check all commitments were generated
    assert p.secret_s is not None
    assert p.commitment_co is not None
    assert p.commitment_cv is not None
    
    # Verify commitment chain
    assert hash_function(p.secret_s) == p.commitment_co
    assert hash_function(p.commitment_co) == p.commitment_cv

def test_participant_signing():
    """Test participant data signing and leader communication."""
    p = Participant("test_participant")
    test_data = b"test data"
    
    # Test direct signing
    signature = p.sign_data(test_data)
    assert verify_signature(p.vk, test_data, signature)
    
    # Test leader communication
    data, signature = p.send_to_leader(test_data, "test")
    assert data == test_data
    assert verify_signature(p.vk, data, signature)