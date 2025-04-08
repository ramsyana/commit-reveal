"""Simulation script for the on-chain Commit-Reveal² protocol.

Demonstrates the full protocol flow including:
- Normal operation with all participants completing the protocol
- Last Revealer Attack simulation
"""

import logging
from typing import List
from random import shuffle
from participant import Participant
from onchain_contract import OnChainCommitReveal2

def run_normal_simulation(num_participants: int = 3) -> bool:
    """Run normal protocol simulation with all participants completing.
    
    Args:
        num_participants: Number of participants to simulate
        
    Returns:
        True if simulation completes successfully
    """
    # Initialize participants
    participants = [
        Participant(f"P{i}") for i in range(num_participants)
    ]
    
    # Initialize contract with participant addresses
    contract = OnChainCommitReveal2({p.address for p in participants})
    
    # COMMIT phase: All participants submit cv
    logging.info("\n=== COMMIT PHASE ===")
    for p in participants:
        p.generate_commitments()
        success = contract.submit_cv(p.address, p.commitment_cv)
        if not success:
            logging.error(f"Failed to submit cv for {p.id}")
            return False
    
    # REVEAL1 phase: All participants submit co (in random order)
    logging.info("\n=== REVEAL1 PHASE ===")
    reveal1_order = participants.copy()
    shuffle(reveal1_order)
    
    for p in reveal1_order:
        success = contract.submit_co(p.address, p.commitment_co)
        if not success:
            logging.error(f"Failed to submit co for {p.id}")
            return False
    
    # REVEAL2 phase: Participants reveal s in computed order
    logging.info("\n=== REVEAL2 PHASE ===")
    for revealer_addr in contract.reveal_order:
        # Find participant with this address
        p = next(p for p in participants if p.address == revealer_addr)
        success = contract.submit_s(p.address, p.secret_s)
        if not success:
            logging.error(f"Failed to submit s for {p.id}")
            return False
    
    # Verify final randomness was generated
    omega_o = contract.get_final_randomness()
    if omega_o is None:
        logging.error("Failed to generate final randomness")
        return False
        
    logging.info(f"Successfully generated randomness: {omega_o.hex()}")
    return True

def simulate_last_revealer_attack(num_participants: int = 3) -> bool:
    """Simulate the Last Revealer Attack scenario.
    
    One participant fails to reveal their secret when it's their turn,
    preventing the protocol from completing.
    
    Args:
        num_participants: Number of participants to simulate
        
    Returns:
        True if attack simulation works as expected
    """
    # Initialize participants
    participants = [
        Participant(f"P{i}") for i in range(num_participants)
    ]
    
    # Initialize contract
    contract = OnChainCommitReveal2({p.address for p in participants})
    
    # COMMIT phase
    logging.info("\n=== ATTACK: COMMIT PHASE ===")
    for p in participants:
        p.generate_commitments()
        contract.submit_cv(p.address, p.commitment_cv)
    
    # REVEAL1 phase
    logging.info("\n=== ATTACK: REVEAL1 PHASE ===")
    reveal1_order = participants.copy()
    shuffle(reveal1_order)
    
    for p in reveal1_order:
        contract.submit_co(p.address, p.commitment_co)
    
    # REVEAL2 phase: Skip last revealer
    logging.info("\n=== ATTACK: REVEAL2 PHASE (Last Revealer Attacks) ===")
    for revealer_addr in contract.reveal_order[:-1]:  # Skip last revealer
        p = next(p for p in participants if p.address == revealer_addr)
        contract.submit_s(p.address, p.secret_s)
    
    # Verify attack prevented randomness generation
    omega_o = contract.get_final_randomness()
    attack_successful = omega_o is None
    
    if attack_successful:
        logging.info("Attack successful: Last revealer prevented randomness generation")
    else:
        logging.error("Attack failed: Randomness was generated despite missing revealer")
        
    return attack_successful

def main():
    """Run both normal operation and attack simulations."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Run normal simulation
    logging.info("\n=== Starting Normal Simulation ===")
    success = run_normal_simulation()
    logging.info(f"Normal simulation {'succeeded' if success else 'failed'}")
    
    # Run attack simulation
    logging.info("\n=== Starting Attack Simulation ===")
    success = simulate_last_revealer_attack()
    logging.info(f"Attack simulation {'succeeded' if success else 'failed'}")

if __name__ == '__main__':
    main()