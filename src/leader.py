from typing import Dict, List, Optional, Tuple
from merkletools import MerkleTools
import logging
import functools
import operator
from .crypto_utils import hash_function, verify_signature, generate_keypair, get_address

class LeaderNode:
    def __init__(self):
        # Leader's own identity
        self.sk, self.vk = generate_keypair()
        self.address = get_address(self.vk)
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Leader initialized with address: {self.address.hex()}")

        # Participant tracking
        self.participants = set()  # Set of participant addresses
        self.address_to_vk = {}  # Map participant address to public key
        self.activated_addresses = []  # List to maintain activation order

        # Off-chain state
        self.received_cv_signed: Dict[str, Tuple[bytes, bytes]] = {}  # address -> (cv, signature)
        self.received_co: Dict[str, bytes] = {}  # address -> co
        self.received_s_signed: Dict[str, Tuple[bytes, bytes]] = {}  # address -> (s, original_cv_signature)

        # Merkle Tree and Reveal Order
        self.merkle_tree = MerkleTools(hash_type='sha3_256')  # Using sha3_256 for simulation compatibility
        self.merkle_root_cv: Optional[bytes] = None
        self.reveal_order: List[str] = []

        # State flags
        self.all_cv_received = False
        self.all_co_received = False
        self.all_s_received = False
    
    def add_participant(self, address: str, public_key: bytes) -> bool:
        """Registers a participant's address and public key."""
        if address not in self.participants:
            self.participants.add(address)
            self.address_to_vk[address] = public_key
            self.activated_addresses.append(address)
            self.logger.info(f"Participant added: {address.hex()}")
            return True
        self.logger.warning(f"Participant already added: {address.hex()}")
        return False
    
    def receive_cv_offchain(self, sender: str, cv: bytes, signature: bytes) -> bool:
        """Receive and verify C_v commitment with signature."""
        if sender not in self.participants:
            self.logger.error(f"Unknown sender: {sender}")
            return False
        
        if sender not in self.address_to_vk:
            self.logger.error(f"Unknown sender: {sender.hex()}")
            return False

        vk = self.address_to_vk[sender]
        if not verify_signature(vk, cv, signature):
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
            cv = self.received_cv_signed[address][0]
            self.merkle_tree.add_leaf(cv.hex(), do_hash=False)
        
        self.merkle_tree.make_tree()
        self.merkle_root_cv = bytes.fromhex(self.merkle_tree.get_merkle_root())
        self.logger.info(f"Built Merkle tree with root: {self.merkle_root_cv.hex()}")
    
    def receive_co_offchain(self, sender: str, co: bytes) -> bool:
        """Receive and verify C_o commitment."""
        if sender not in self.participants:
            self.logger.error(f"Unknown sender: {sender}")
            return False
        
        if sender not in self.received_cv_signed:
            self.logger.error(f"No verified C_v received from {sender.hex()} to verify C_o against.")
            return False

        expected_cv = self.received_cv_signed[sender][0]  # Get the stored cv
        if hash_function(co) != expected_cv:
            self.logger.error(f"Invalid C_o from {sender.hex()}: Hash(co) != stored C_v")
            return False
        
        self.received_co[sender] = co
        self.logger.info(f"Received valid C_o from {sender}")
        
        if len(self.received_co) == len(self.participants):
            self._compute_reveal_order_offchain()
        return True
    
    def _compute_reveal_order_offchain(self) -> None:
        """Computes omega_v and the reveal order based on received C_v values."""
        if not self.all_cv_received:
            self.logger.error("Cannot compute reveal order before all C_v are received.")
            return

        # Extract C_v values IN ACTIVATION ORDER
        all_cvs_ordered = []
        for addr in self.activated_addresses:
            if addr in self.received_cv_signed:
                all_cvs_ordered.append(self.received_cv_signed[addr][0])
            else:
                self.logger.error(f"Missing C_v for activated address {addr.hex()} when computing order.")
                return # Cannot compute order if C_v is missing

        if not all_cvs_ordered:
            self.logger.warning("No C_v commitments available to compute reveal order.")
            self.omega_v = b'\x00' * 32 # Or handle appropriately
        else:
            # Calculate byte-wise XOR sum across all ordered C_v values
            self.omega_v = bytes(functools.reduce(operator.xor, byte_tuple)
                                for byte_tuple in zip(*all_cvs_ordered))

        self.logger.info(f"Computed omega_v: {self.omega_v.hex()}")

        # Compute d_i values and sort participants based on them
        reveal_metrics = {}
        for addr in self.activated_addresses:
            cv = self.received_cv_signed[addr][0] # Get the participant's C_v
            # d_i = H(|Ωv - Cv,i|) -> Use XOR for difference with bytes
            xor_diff = bytes(a ^ b for a, b in zip(self.omega_v, cv))
            d_i = hash_function(xor_diff)
            reveal_metrics[addr] = d_i
            self.logger.debug(f"d_i for {addr.hex()}: {d_i.hex()}")

        # Sort addresses based on d_i values (lexicographical sort on hash bytes)
        self.reveal_order = sorted(reveal_metrics.keys(), key=lambda addr: reveal_metrics[addr])

        self.logger.info(f"Computed reveal order: {[addr.hex() for addr in self.reveal_order]}")
    
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
        
        # Get the original signature from C_v submission
        cv_data = self.received_cv_signed[sender]
        original_sig = cv_data[1]  # Get signature from tuple
        
        self.received_s_signed[sender] = (s, original_sig)
        self.logger.info(f"Received valid secret from {sender.hex()}")
        
        if len(self.received_s_signed) == len(self.participants):
            self.logger.info("All secrets received")
            self.all_s_received = True
        return True
    
    def get_final_submission_data(self) -> Optional[Tuple[List[bytes], List[bytes]]]:
        """Prepare final data for contract submission."""
        if not self.all_s_received:
            return None
        
        secrets = []
        signatures = []
        
        # Order by activation order
        for address in self.activated_addresses:
            s_data = self.received_s_signed[address]
            secrets.append(s_data[0])  # Get secret from tuple
            signatures.append(s_data[1])  # Get signature from tuple
        
        return secrets, signatures