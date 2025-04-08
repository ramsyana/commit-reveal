"""Tests for the On-Chain Commit-Reveal² implementation.

Tests cover:
- Contract state transitions
- Commitment submissions and verifications
- Reveal order computation
- Edge cases with varying participant numbers
- Security simulations (last revealer mitigation)
"""

import pytest
from src.onchain_contract import OnChainCommitReveal2, Phase
from src.participant import Participant
from src.crypto_utils import hash_function

@pytest.fixture
def participants():
    """Create a set of test participants."""
    return [Participant(f"p{i}") for i in range(3)]

@pytest.fixture
def contract(participants):
    """Initialize contract with participant addresses."""
    addresses = {p.address for p in participants}
    return OnChainCommitReveal2(addresses)

def test_contract_initialization(contract, participants):
    """Test contract initialization."""
    assert contract.phase == Phase.COMMIT
    assert len(contract.participant_addresses) == len(participants)
    assert not contract.commitments_cv
    assert not contract.commitments_co
    assert not contract.revealed_secrets_s

def test_cv_submission(contract, participants):
    """Test cv commitment submission phase."""
    # Generate commitments for all participants
    for p in participants:
        p.generate_commitments()
        assert contract.submit_cv(p.address, p.commitment_cv)
    
    # Verify phase transition
    assert contract.phase == Phase.REVEAL1
    
    # Test invalid submissions
    p = participants[0]
    assert not contract.submit_cv(p.address, p.commitment_cv)  # Duplicate
    assert not contract.submit_cv(b'invalid', p.commitment_cv)  # Unknown address

def test_co_submission(contract, participants):
    """Test co commitment submission and reveal order computation."""
    # Submit all cv first
    for p in participants:
        p.generate_commitments()
        contract.submit_cv(p.address, p.commitment_cv)
    
    # Submit co values
    for p in participants:
        assert contract.submit_co(p.address, p.commitment_co)
    
    # Verify reveal order computation
    assert len(contract.reveal_order) == len(participants)
    assert contract.omega_v is not None
    assert contract.phase == Phase.REVEAL2

def test_s_submission(contract, participants):
    """Test secret submission in correct reveal order."""
    # Complete previous phases
    for p in participants:
        p.generate_commitments()
        contract.submit_cv(p.address, p.commitment_cv)
    for p in participants:
        contract.submit_co(p.address, p.commitment_co)
    
    # Submit secrets in reveal order
    for addr in contract.reveal_order:
        p = next(p for p in participants if p.address == addr)
        assert contract.submit_s(p.address, p.secret_s)
    
    assert contract.phase == Phase.DONE
    assert contract.omega_o is not None

def test_invalid_reveal_order(contract, participants):
    """Test rejection of out-of-order secret submission."""
    # Complete previous phases
    for p in participants:
        p.generate_commitments()
        contract.submit_cv(p.address, p.commitment_cv)
    for p in participants:
        contract.submit_co(p.address, p.commitment_co)
    
    # Try to submit secret out of order
    wrong_p = next(p for p in participants if p.address != contract.reveal_order[0])
    assert not contract.submit_s(wrong_p.address, wrong_p.secret_s)

@pytest.mark.parametrize("num_participants", [2, 10, 50])
def test_participant_scaling(num_participants):
    """Test protocol with different numbers of participants."""
    participants = [Participant(f"p{i}") for i in range(num_participants)]
    addresses = {p.address for p in participants}
    contract = OnChainCommitReveal2(addresses)
    
    # Run full protocol
    for p in participants:
        p.generate_commitments()
        contract.submit_cv(p.address, p.commitment_cv)
    
    for p in participants:
        contract.submit_co(p.address, p.commitment_co)
    
    for addr in contract.reveal_order:
        p = next(p for p in participants if p.address == addr)
        contract.submit_s(p.address, p.secret_s)
    
    assert contract.phase == Phase.DONE
    assert contract.omega_o is not None

def test_last_revealer_mitigation():
    """Test that reveal position cannot be predicted before cv submission."""
    # Create participants
    participants = [Participant(f"p{i}") for i in range(5)]
    addresses = {p.address for p in participants}
    
    # Run multiple simulations with same participants
    reveal_positions = {p.id: [] for p in participants}
    
    for _ in range(10):  # Run 10 simulations
        contract = OnChainCommitReveal2(addresses)
        
        # New commitments each time
        for p in participants:
            p.generate_commitments()
            contract.submit_cv(p.address, p.commitment_cv)
        
        for p in participants:
            contract.submit_co(p.address, p.commitment_co)
        
        # Record positions
        for pos, addr in enumerate(contract.reveal_order):
            p = next(p for p in participants if p.address == addr)
            reveal_positions[p.id].append(pos)
    
    # Verify positions vary
    for positions in reveal_positions.values():
        assert len(set(positions)) > 1  # Should have different positions