"""Simulated smart contract for the on-chain Commit-Reveal² protocol.

Manages the protocol phases and state transitions:
COMMIT -> REVEAL1 -> REVEAL2 -> DONE

Handles commitment submissions and verifications:
- cv commitments in COMMIT phase
- co commitments in REVEAL1 phase
- s secrets in REVEAL2 phase
"""

from typing import Dict, List, Optional, Set
from enum import Enum, auto
import logging
from crypto_utils import hash_function

class Phase(Enum):
    """Protocol phases"""
    COMMIT = auto()
    REVEAL1 = auto()
    REVEAL2 = auto()
    DONE = auto()

class OnChainCommitReveal2:
    def __init__(self, participant_addresses: Set[bytes]):
        """Initialize contract with participant addresses.
        
        Args:
            participant_addresses: Set of participant addresses
        """
        self.participant_addresses = participant_addresses
        self.phase = Phase.COMMIT
        
        # Commitment storage
        self.commitments_cv: Dict[bytes, bytes] = {}
        self.commitments_co: Dict[bytes, bytes] = {}
        self.revealed_secrets_s: Dict[bytes, bytes] = {}
        
        # Reveal order computation
        self.reveal_order_metrics: Dict[bytes, int] = {}
        self.omega_v: Optional[bytes] = None
        self.reveal_order: List[bytes] = []
        
        # Final randomness
        self.omega_o: Optional[bytes] = None
        
        logging.info(f"Initialized contract with {len(participant_addresses)} participants")
    
    def submit_cv(self, sender_address: bytes, cv: bytes) -> bool:
        """Submit initial commitment cv in COMMIT phase.
        
        Args:
            sender_address: Address of submitting participant
            cv: The cv commitment (H(H(s)))
            
        Returns:
            True if submission accepted, False otherwise
        """
        if self.phase != Phase.COMMIT:
            logging.warning(f"Invalid phase for cv submission: {self.phase}")
            return False
            
        if sender_address not in self.participant_addresses:
            logging.warning(f"Unknown participant address: {sender_address.hex()}")
            return False
            
        if sender_address in self.commitments_cv:
            logging.warning(f"Duplicate cv submission from: {sender_address.hex()}")
            return False
        
        self.commitments_cv[sender_address] = cv
        logging.info(f"Accepted cv from {sender_address.hex()}")
        
        # Check if all participants have submitted
        if len(self.commitments_cv) == len(self.participant_addresses):
            self.phase = Phase.REVEAL1
            logging.info("Advanced to REVEAL1 phase")
            
        return True
    
    def submit_co(self, sender_address: bytes, co: bytes) -> bool:
        """Submit co commitment in REVEAL1 phase.
        
        Args:
            sender_address: Address of submitting participant
            co: The co commitment (H(s))
            
        Returns:
            True if submission accepted, False otherwise
        """
        if self.phase != Phase.REVEAL1:
            logging.warning(f"Invalid phase for co submission: {self.phase}")
            return False
            
        if sender_address not in self.participant_addresses:
            logging.warning(f"Unknown participant address: {sender_address.hex()}")
            return False
            
        if sender_address in self.commitments_co:
            logging.warning(f"Duplicate co submission from: {sender_address.hex()}")
            return False
            
        # Verify co matches previously submitted cv
        expected_cv = hash_function(co)
        if expected_cv != self.commitments_cv[sender_address]:
            logging.warning(f"Invalid co from {sender_address.hex()}: hash mismatch")
            return False
        
        self.commitments_co[sender_address] = co
        logging.info(f"Accepted co from {sender_address.hex()}")
        
        # If all revealed, compute omega_v and reveal order
        if len(self.commitments_co) == len(self.participant_addresses):
            self._compute_reveal_order()
            self.phase = Phase.REVEAL2
            logging.info("Advanced to REVEAL2 phase")
            
        return True
    
    def submit_s(self, sender_address: bytes, s: bytes) -> bool:
        """Submit secret s in REVEAL2 phase.
        
        Args:
            sender_address: Address of submitting participant
            s: The original secret
            
        Returns:
            True if submission accepted, False otherwise
        """
        if self.phase != Phase.REVEAL2:
            logging.warning(f"Invalid phase for s submission: {self.phase}")
            return False
            
        if sender_address not in self.participant_addresses:
            logging.warning(f"Unknown participant address: {sender_address.hex()}")
            return False
            
        if sender_address in self.revealed_secrets_s:
            logging.warning(f"Duplicate s submission from: {sender_address.hex()}")
            return False
        
        # Verify s matches previously submitted co
        expected_co = hash_function(s)
        if expected_co != self.commitments_co[sender_address]:
            logging.warning(f"Invalid s from {sender_address.hex()}: hash mismatch")
            return False
            
        # Verify reveal order
        next_revealer = self.reveal_order[len(self.revealed_secrets_s)]
        if sender_address != next_revealer:
            logging.warning(f"Invalid reveal order: expected {next_revealer.hex()}, got {sender_address.hex()}")
            return False
        
        self.revealed_secrets_s[sender_address] = s
        logging.info(f"Accepted s from {sender_address.hex()}")
        
        # If all revealed, compute final randomness
        if len(self.revealed_secrets_s) == len(self.participant_addresses):
            self._compute_final_randomness()
            self.phase = Phase.DONE
            logging.info("Advanced to DONE phase")
            
        return True
    
    def _compute_reveal_order(self) -> None:
        """Compute reveal order based on cv commitments.
        
        Sets omega_v = XOR of all cv values
        For each participant i: d_i = H(|omega_v - cv_i|)
        Orders participants by d_i values (ascending)
        """
        # Compute omega_v (XOR of all cv values)
        omega_v = bytes(a ^ b for a, b in zip(*self.commitments_cv.values()))
        self.omega_v = omega_v
        
        # Compute d_i values for ordering
        for addr, cv in self.commitments_cv.items():
            # Compute |omega_v - cv_i| as XOR of the values
            diff = bytes(a ^ b for a, b in zip(omega_v, cv))
            d_i = int.from_bytes(hash_function(diff), 'big')
            self.reveal_order_metrics[addr] = d_i
        
        # Sort addresses by d_i values
        self.reveal_order = sorted(
            self.participant_addresses,
            key=lambda addr: self.reveal_order_metrics[addr]
        )
        
        logging.info(f"Computed reveal order for {len(self.reveal_order)} participants")
    
    def _compute_final_randomness(self) -> None:
        """Compute final randomness omega_o = H(s1||s2||...||sn).
        
        Concatenates secrets in reveal order and hashes.
        """
        # Concatenate secrets in reveal order
        ordered_secrets = [self.revealed_secrets_s[addr] for addr in self.reveal_order]
        combined = b''.join(ordered_secrets)
        
        # Hash to get final randomness
        self.omega_o = hash_function(combined)
        logging.info(f"Computed final randomness: {self.omega_o.hex()}")
    
    def get_final_randomness(self) -> Optional[bytes]:
        """Get the final random value if protocol is complete.
        
        Returns:
            omega_o if in DONE phase, None otherwise
        """
        return self.omega_o if self.phase == Phase.DONE else None
    
    def reset(self) -> None:
        """Reset contract state for testing."""
        self.phase = Phase.COMMIT
        self.commitments_cv.clear()
        self.commitments_co.clear()
        self.revealed_secrets_s.clear()
        self.reveal_order_metrics.clear()
        self.omega_v = None
        self.reveal_order.clear()
        self.omega_o = None
        logging.info("Reset contract state")