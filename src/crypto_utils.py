"""Cryptographic utility functions for the Commit-Reveal² protocol.

This module provides core cryptographic operations including:
- Keccak-256 hashing
- Secure secret generation
- ECDSA keypair generation and signing
- Address derivation from public keys
"""

from typing import Tuple, Union
import secrets
import sha3
from ecdsa import SigningKey, VerifyingKey, SECP256k1

def hash_function(data: Union[str, bytes]) -> bytes:
    """Generate Keccak-256 hash of input data.
    
    Args:
        data: Input data to hash (string or bytes)
        
    Returns:
        32-byte Keccak-256 hash
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    keccak = sha3.keccak_256()
    keccak.update(data)
    return keccak.digest()

def generate_secret() -> bytes:
    """Generate a cryptographically secure 32-byte secret.
    
    Returns:
        32 random bytes
    """
    return secrets.token_bytes(32)

def generate_keypair() -> Tuple[SigningKey, VerifyingKey]:
    """Generate ECDSA keypair using SECP256k1 curve.
    
    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key, public_key

def sign_message(private_key: SigningKey, message: Union[str, bytes]) -> bytes:
    """Sign a message using ECDSA.
    
    Args:
        private_key: ECDSA signing key
        message: Message to sign (string or bytes)
        
    Returns:
        Signature bytes
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    return private_key.sign(message)

def verify_signature(public_key: VerifyingKey, message: Union[str, bytes], 
                    signature: bytes) -> bool:
    """Verify an ECDSA signature.
    
    Args:
        public_key: ECDSA verifying key
        message: Original message (string or bytes)
        signature: Signature to verify
        
    Returns:
        True if signature is valid, False otherwise
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    try:
        public_key.verify(signature, message)
        return True
    except:
        return False

def get_address(public_key: VerifyingKey) -> bytes:
    """Derive an Ethereum-style address from a public key.
    
    Takes the Keccak-256 hash of the public key and returns the last 20 bytes.
    
    Args:
        public_key: ECDSA verifying key
        
    Returns:
        20-byte address
    """
    pub_bytes = public_key.to_string()
    return hash_function(pub_bytes)[-20:] # Take last 20 bytes