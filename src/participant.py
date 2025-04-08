"""Participant class for the Commit-Reveal² protocol.

Handles participant operations including:
- Key management and addressing
- Commitment generation (s, co, cv)
- Data signing and leader communication
"""

from typing import Tuple, Optional
import logging
from ecdsa import SigningKey, VerifyingKey
from crypto_utils import (
    generate_keypair,
    generate_secret,
    hash_function,
    sign_message,
    get_address
)

class Participant:
    def __init__(self, id: str):
        """Initialize a new participant.
        
        Args:
            id: Unique identifier for this participant
        """
        self.id = id
        self.sk, self.vk = generate_keypair()
        self.address = get_address(self.vk)
        
        # Commitment values
        self.secret_s: Optional[bytes] = None
        self.commitment_co: Optional[bytes] = None
        self.commitment_cv: Optional[bytes] = None
        
        logging.info(f"Initialized participant {id} with address {self.address.hex()}")
    
    def generate_commitments(self) -> None:
        """Generate the commitment chain s -> co -> cv.
        
        Generates a random secret s, then derives:
        co = H(s)
        cv = H(co)
        """
        self.secret_s = generate_secret()
        self.commitment_co = hash_function(self.secret_s)
        self.commitment_cv = hash_function(self.commitment_co)
        
        logging.info(f"Participant {self.id} generated commitments")
        
    def sign_data(self, data: bytes) -> bytes:
        """Sign data using participant's private key.
        
        Args:
            data: Data to sign
            
        Returns:
            Signature bytes
        """
        return sign_message(self.sk, data)
    
    def send_to_leader(self, data: bytes, data_type: str) -> Tuple[bytes, bytes]:
        """Simulate sending signed data to the leader node.
        
        Args:
            data: Data to send
            data_type: Type of data being sent (for logging)
            
        Returns:
            Tuple of (data, signature)
        """
        signature = self.sign_data(data)
        logging.info(f"Participant {self.id} sending {data_type} to leader")
        return data, signature