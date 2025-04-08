from typing import Dict, List, Optional, Tuple
from enum import Enum, auto
from merkletools import MerkleTools
import logging
from crypto_utils import hash_function, verify_signature

class Phase(Enum):
    AWAITING_ROOT = auto()
    AWAITING_SECRETS = auto()
    DONE = auto()

class HybridContract:
    def __init__(self, leader_address: str):
        self.leader_address = leader_address
        self.participant_vks: Dict[str, bytes] = {}  # address -> verification key
        self.activated_addresses: List[str] = []  # Maintain activation order
        self.merkle_root_cv: Optional[bytes] = None
        self.omega_o: Optional[bytes] = None
        self.phase = Phase.AWAITING_ROOT
        self.merkle_tree = MerkleTools(hash_type='keccak_256')
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def add_participant(self, address: str, verification_key: bytes) -> None:
        """Register a participant with their verification key."""
        if address not in self.participant_vks:
            self.participant_vks[address] = verification_key
            self.activated_addresses.append(address)
            self.logger.info(f"Registered participant: {address}")
    
    def submit_merkle_root_cv(self, sender_address: str, root: bytes) -> bool:
        """Submit Merkle root of C_v values."""
        if sender_address != self.leader_address:
            self.logger.error("Only leader can submit Merkle root")
            return False
        
        if self.phase != Phase.AWAITING_ROOT:
            self.logger.error(f"Invalid phase for root submission: {self.phase}")
            return False
        
        self.merkle_root_cv = root
        self.phase = Phase.AWAITING_SECRETS
        self.logger.info(f"Merkle root submitted: {root.hex()}")
        return True
    
    def generate_random_number(self, sender_address: str, secrets: List[bytes], 
                             signatures: List[bytes]) -> bool:
        """Generate final random number from submitted secrets and signatures."""
        if sender_address != self.leader_address:
            self.logger.error("Only leader can submit final data")
            return False
        
        if self.phase != Phase.AWAITING_SECRETS:
            self.logger.error(f"Invalid phase for secret submission: {self.phase}")
            return False
        
        if len(secrets) != len(self.activated_addresses) or \
           len(signatures) != len(self.activated_addresses):
            self.logger.error("Mismatched number of secrets or signatures")
            return False
        
        # Reset Merkle tree for verification
        self.merkle_tree.reset_tree()
        
        # Verify each secret and signature, rebuild Merkle tree
        for i, address in enumerate(self.activated_addresses):
            s = secrets[i]
            sig = signatures[i]
            vk = self.participant_vks[address]
            
            # Recompute commitments
            co = hash_function(s)
            cv = hash_function(co)
            
            # Verify signature on C_v
            if not verify_signature(vk, cv, sig):
                self.logger.error(f"Invalid signature from {address}")
                return False
            
            # Add to Merkle tree
            self.merkle_tree.add_leaf(cv.hex(), do_hash=False)
        
        # Build tree and verify root matches
        self.merkle_tree.make_tree()
        computed_root = bytes.fromhex(self.merkle_tree.get_merkle_root())
        if computed_root != self.merkle_root_cv:
            self.logger.error("Merkle root mismatch")
            return False
        
        # All verified, compute final randomness
        concat_secrets = b''.join(secrets)
        self.omega_o = hash_function(concat_secrets)
        self.phase = Phase.DONE
        self.logger.info(f"Random number generated: {self.omega_o.hex()}")
        return True
    
    def get_final_randomness(self) -> Optional[bytes]:
        """Return the final random number if available."""
        if self.phase != Phase.DONE:
            return None
        return self.omega_o
    
    def reset(self) -> None:
        """Reset contract state for testing."""
        self.merkle_root_cv = None
        self.omega_o = None
        self.phase = Phase.AWAITING_ROOT
        self.merkle_tree.reset_tree()
        self.logger.info("Contract state reset")