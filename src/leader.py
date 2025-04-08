from typing import Dict, List, Optional, Tuple
from merkletools import MerkleTools
import logging
from crypto_utils import hash_function, verify_signature

class LeaderNode:
    def __init__(self):
        self.participants = set()  # Set of participant addresses
        self.activated_addresses = []  # List to maintain activation order
        self.received_cv_signed: Dict[str, Tuple[bytes, bytes]] = {}  # address -> (cv, signature)
        self.received_co: Dict[str, bytes] = {}  # address -> co
        self.received_s_signed: Dict[str, Tuple[bytes, bytes]] = {}  # address -> (s, original_cv_signature)
        self.merkle_root_cv: Optional[bytes] = None
        self.reveal_order: List[str] = []
        self.merkle_tree = MerkleTools(hash_type='sha3_256')  # Using sha3_256 for simulation compatibility
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def add_participant(self, address: str) -> None:
        """Add a participant to the protocol."""
        if address not in self.participants:
            self.participants.add(address)
            self.activated_addresses.append(address)
            self.logger.info(f"Added participant: {address}")
    
    def receive_cv_offchain(self, sender: str, cv: bytes, signature: bytes) -> bool:
        """Receive and verify C_v commitment with signature."""
        if sender not in self.participants:
            self.logger.error(f"Unknown sender: {sender}")
            return False
        
        if not verify_signature(sender, cv, signature):
            self.logger.error(f"Invalid signature from {sender}")
            return False
        
        self.received_cv_signed[sender] = (cv, signature)
        self.logger.info(f"Received valid C_v from {sender}")
        
        if len(self.received_cv_signed) == len(self.participants):
            self._build_merkle_tree_cv()
        return True
    
    def _build_merkle_tree_cv(self) -> None:
        """Build Merkle tree from C_v values in activation order."""
        self.merkle_tree.reset_tree()
        
        # Add leaves in activation order
        for address in self.activated_addresses:
            cv, _ = self.received_cv_signed[address]
            self.merkle_tree.add_leaf(cv.hex(), do_hash=False)
        
        self.merkle_tree.make_tree()
        self.merkle_root_cv = bytes.fromhex(self.merkle_tree.get_merkle_root())
        self.logger.info(f"Built Merkle tree with root: {self.merkle_root_cv.hex()}")
    
    def receive_co_offchain(self, sender: str, co: bytes) -> bool:
        """Receive and verify C_o commitment."""
        if sender not in self.participants:
            self.logger.error(f"Unknown sender: {sender}")
            return False
        
        cv, _ = self.received_cv_signed.get(sender, (None, None))
        if cv is None:
            self.logger.error(f"No C_v received from {sender}")
            return False
        
        if hash_function(co) != cv:
            self.logger.error(f"Invalid C_o from {sender}: hash mismatch")
            return False
        
        self.received_co[sender] = co
        self.logger.info(f"Received valid C_o from {sender}")
        
        if len(self.received_co) == len(self.participants):
            self._compute_reveal_order_offchain()
        return True
    
    def _compute_reveal_order_offchain(self) -> None:
        """Compute reveal order based on C_v values."""
        # Compute omega_v (XOR of all C_v values)
        omega_v = bytes(a ^ b for a, b in zip(*[cv for cv, _ in self.received_cv_signed.values()]))
        
        # Calculate d_i values and create ordered list
        d_values = []
        for address in self.activated_addresses:
            cv, _ = self.received_cv_signed[address]
            # Calculate |Ωv - Cv,i| as XOR distance
            xor_diff = bytes(a ^ b for a, b in zip(omega_v, cv))
            d_i = hash_function(xor_diff)
            d_values.append((d_i, address))
        
        # Sort by d_i values
        d_values.sort(key=lambda x: x[0])
        self.reveal_order = [addr for _, addr in d_values]
        self.logger.info(f"Computed reveal order: {self.reveal_order}")
    
    def receive_s_offchain(self, sender: str, s: bytes) -> bool:
        """Receive and verify secret S."""
        if sender not in self.participants:
            self.logger.error(f"Unknown sender: {sender}")
            return False
        
        if not self.reveal_order:
            self.logger.error("Reveal order not yet computed")
            return False
        
        expected_sender = self.reveal_order[len(self.received_s_signed)]
        if sender != expected_sender:
            self.logger.error(f"Wrong reveal order. Expected: {expected_sender}, got: {sender}")
            return False
        
        co = self.received_co.get(sender)
        if co is None:
            self.logger.error(f"No C_o received from {sender}")
            return False
        
        if hash_function(s) != co:
            self.logger.error(f"Invalid secret from {sender}: hash mismatch")
            return False
        
        _, original_sig = self.received_cv_signed[sender]
        self.received_s_signed[sender] = (s, original_sig)
        self.logger.info(f"Received valid secret from {sender}")
        
        if len(self.received_s_signed) == len(self.participants):
            self.logger.info("All secrets received")
        return True
    
    def get_final_submission_data(self) -> Optional[Tuple[List[bytes], List[bytes]]]:
        """Prepare final data for contract submission."""
        if len(self.received_s_signed) != len(self.participants):
            return None
        
        secrets = []
        signatures = []
        
        # Order by activation order
        for address in self.activated_addresses:
            s, sig = self.received_s_signed[address]
            secrets.append(s)
            signatures.append(sig)
        
        return secrets, signatures