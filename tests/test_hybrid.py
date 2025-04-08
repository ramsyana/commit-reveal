"""Tests for the Hybrid Commit-Reveal² implementation.

Tests cover:
- Leader node operations
- Merkle tree construction and verification
- Contract state transitions
- Off-chain communication simulation
- Edge cases and security considerations
"""

import pytest
from src.hybrid_contract import HybridContract, Phase
from src.leader import LeaderNode
from src.participant import Participant
from src.crypto_utils import hash_function, verify_signature

@pytest.fixture
def participants():
    """Create a set of test participants."""
    return [Participant(f"p{i}") for i in range(3)]

@pytest.fixture
def leader():
    """Initialize leader node."""
    return LeaderNode()

@pytest.fixture
def contract(leader):
    """Initialize hybrid contract with leader address."""
    return HybridContract(leader.address)

def test_leader_initialization(leader, participants):
    """Test leader node initialization and participant registration."""
    for p in participants:
        leader.add_participant(p.address)
    
    assert len(leader.participants) == len(participants)
    assert len(leader.activated_addresses) == len(participants)

def test_cv_collection(leader, participants):
    """Test C_v commitment collection and Merkle tree construction."""
    # Register participants
    for p in participants:
        leader.add_participant(p.address)
        p.generate_commitments()
    
    # Submit C_v values
    for p in participants:
        data, signature = p.send_to_leader(p.commitment_cv, "C_v")
        assert leader.receive_cv_offchain(p.address, data, signature)
    
    assert leader.merkle_root_cv is not None

def test_co_collection(leader, participants):
    """Test C_o commitment collection and reveal order computation."""
    # Setup and C_v submission
    for p in participants:
        leader.add_participant(p.address)
        p.generate_commitments()
        data, signature = p.send_to_leader(p.commitment_cv, "C_v")
        leader.receive_cv_offchain(p.address, data, signature)
    
    # Submit C_o values
    for p in participants:
        assert leader.receive_co_offchain(p.address, p.commitment_co)
    
    assert leader.reveal_order
    assert len(leader.reveal_order) == len(participants)

def test_s_collection(leader, participants):
    """Test secret collection in reveal order."""
    # Complete previous phases
    for p in participants:
        leader.add_participant(p.address)
        p.generate_commitments()
        data, signature = p.send_to_leader(p.commitment_cv, "C_v")
        leader.receive_cv_offchain(p.address, data, signature)
    
    for p in participants:
        leader.receive_co_offchain(p.address, p.commitment_co)
    
    # Submit secrets in reveal order
    for addr in leader.reveal_order:
        p = next(p for p in participants if p.address == addr)
        assert leader.receive_s_offchain(p.address, p.secret_s)

def test_contract_integration(contract, leader, participants):
    """Test full contract integration with leader and participants."""
    # Register participants with contract and leader
    for p in participants:
        contract.add_participant(p.address, p.vk)
        leader.add_participant(p.address)
        p.generate_commitments()
    
    # Collect C_v commitments
    for p in participants:
        data, signature = p.send_to_leader(p.commitment_cv, "C_v")
        leader.receive_cv_offchain(p.address, data, signature)
    
    # Submit Merkle root
    assert contract.submit_merkle_root_cv(leader.address, leader.merkle_root_cv)
    assert contract.phase == Phase.AWAITING_SECRETS
    
    # Collect C_o and compute reveal order
    for p in participants:
        leader.receive_co_offchain(p.address, p.commitment_co)
    
    # Collect secrets in order
    for addr in leader.reveal_order:
        p = next(p for p in participants if p.address == addr)
        leader.receive_s_offchain(p.address, p.secret_s)
    
    # Submit final data
    secrets = []
    signatures = []
    for addr in contract.activated_addresses:
        s, sig = leader.received_s_signed[addr]
        secrets.append(s)
        signatures.append(sig)
    
    assert contract.generate_random_number(leader.address, secrets, signatures)
    assert contract.phase == Phase.DONE
    assert contract.omega_o is not None

@pytest.mark.parametrize("num_participants", [2, 10, 50])
def test_participant_scaling(num_participants):
    """Test protocol with different numbers of participants."""
    participants = [Participant(f"p{i}") for i in range(num_participants)]
    leader = LeaderNode()
    contract = HybridContract(leader.address)
    
    # Register participants
    for p in participants:
        contract.add_participant(p.address, p.vk)
        leader.add_participant(p.address)
        p.generate_commitments()
    
    # Run protocol
    for p in participants:
        data, signature = p.send_to_leader(p.commitment_cv, "C_v")
        leader.receive_cv_offchain(p.address, data, signature)
    
    contract.submit_merkle_root_cv(leader.address, leader.merkle_root_cv)
    
    for p in participants:
        leader.receive_co_offchain(p.address, p.commitment_co)
    
    for addr in leader.reveal_order:
        p = next(p for p in participants if p.address == addr)
        leader.receive_s_offchain(p.address, p.secret_s)
    
    # Submit final data
    secrets = []
    signatures = []
    for addr in contract.activated_addresses:
        s, sig = leader.received_s_signed[addr]
        secrets.append(s)
        signatures.append(sig)
    
    assert contract.generate_random_number(leader.address, secrets, signatures)
    assert contract.phase == Phase.DONE

def test_invalid_merkle_proof():
    """Test rejection of invalid Merkle proofs."""
    participants = [Participant(f"p{i}") for i in range(3)]
    leader = LeaderNode()
    contract = HybridContract(leader.address)
    
    # Setup participants
    for p in participants:
        contract.add_participant(p.address, p.vk)
        leader.add_participant(p.address)
        p.generate_commitments()
    
    # Collect commitments
    for p in participants:
        data, signature = p.send_to_leader(p.commitment_cv, "C_v")
        leader.receive_cv_offchain(p.address, data, signature)
    
    # Try to submit modified root
    modified_root = bytes([x ^ 1 for x in leader.merkle_root_cv])  # Flip bits
    assert not contract.submit_merkle_root_cv(leader.address, modified_root)

def test_security_simulation():
    """Test that reveal order remains unpredictable."""
    participants = [Participant(f"p{i}") for i in range(5)]
    reveal_positions = {p.id: [] for p in participants}
    
    # Run multiple simulations
    for _ in range(10):
        leader = LeaderNode()
        
        # Register participants
        for p in participants:
            leader.add_participant(p.address)
            p.generate_commitments()
        
        # Submit commitments
        for p in participants:
            data, signature = p.send_to_leader(p.commitment_cv, "C_v")
            leader.receive_cv_offchain(p.address, data, signature)
        
        for p in participants:
            leader.receive_co_offchain(p.address, p.commitment_co)
        
        # Record positions
        for pos, addr in enumerate(leader.reveal_order):
            p = next(p for p in participants if p.address == addr)
            reveal_positions[p.id].append(pos)
    
    # Verify positions vary
    for positions in reveal_positions.values():
        assert len(set(positions)) > 1  # Should have different positions"