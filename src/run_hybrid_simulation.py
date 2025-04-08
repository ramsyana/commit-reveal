import logging
from typing import List
from participant import Participant
from leader import LeaderNode
from hybrid_contract import HybridContract
import time

class HybridSimulation:
    def __init__(self, num_participants: int = 3):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize participants
        self.participants: List[Participant] = [
            Participant(f"participant_{i}") for i in range(num_participants)
        ]
        
        # Initialize leader
        self.leader = LeaderNode()
        
        # Initialize contract with leader's address
        self.contract = HybridContract(self.leader.address)
        
        # Register participants with both leader and contract
        for p in self.participants:
            self.leader.add_participant(p.address)
            self.contract.add_participant(p.address, p.vk)
    
    def run_simulation(self, simulate_failures: bool = False) -> bool:
        """Run the complete hybrid protocol simulation."""
        try:
            # Phase 1: Offline Commit C_v
            self.logger.info("=== Starting Offline Commit Phase (C_v) ===")
            for p in self.participants:
                p.generate_commitments()
                cv_data = p.commitment_cv
                signature = p.sign_data(cv_data)
                success = self.leader.receive_cv_offchain(p.address, cv_data, signature)
                if not success:
                    self.logger.error(f"Failed to process C_v from {p.address}")
                    return False
            
            # Phase 2: Onchain Submit Root
            self.logger.info("=== Starting Onchain Root Submission ===")
            if not self.contract.submit_merkle_root_cv(
                self.leader.address, 
                self.leader.merkle_root_cv
            ):
                self.logger.error("Failed to submit Merkle root")
                return False
            
            # Phase 3: Offline Reveal C_o
            self.logger.info("=== Starting Offline Reveal Phase (C_o) ===")
            for p in self.participants:
                success = self.leader.receive_co_offchain(p.address, p.commitment_co)
                if not success:
                    self.logger.error(f"Failed to process C_o from {p.address}")
                    return False
            
            # Phase 4: Offline Reveal S
            self.logger.info("=== Starting Offline Reveal Phase (S) ===")
            for address in self.leader.reveal_order:
                participant = next(p for p in self.participants if p.address == address)
                
                # Simulate network failure if requested
                if simulate_failures and address == self.leader.reveal_order[-1]:
                    self.logger.warning("Simulating last participant failure")
                    break
                
                success = self.leader.receive_s_offchain(address, participant.secret_s)
                if not success:
                    self.logger.error(f"Failed to process secret from {address}")
                    return False
                
                # Simulate network delay
                time.sleep(0.1)
            
            # Phase 5: Onchain Final Submit
            self.logger.info("=== Starting Onchain Final Submission ===")
            final_data = self.leader.get_final_submission_data()
            if final_data is None:
                self.logger.error("Failed to get final submission data")
                return False
            
            secrets, signatures = final_data
            if not self.contract.generate_random_number(
                self.leader.address,
                secrets,
                signatures
            ):
                self.logger.error("Failed to generate random number")
                return False
            
            # Get final randomness
            omega_o = self.contract.get_final_randomness()
            self.logger.info(f"Final randomness: {omega_o.hex() if omega_o else None}")
            return True
            
        except Exception as e:
            self.logger.error(f"Simulation failed: {str(e)}")
            return False

def main():
    # Run normal simulation
    sim = HybridSimulation(num_participants=3)
    success = sim.run_simulation()
    print(f"\nNormal simulation {'succeeded' if success else 'failed'}\n")
    
    # Run simulation with failure scenario
    sim = HybridSimulation(num_participants=3)
    success = sim.run_simulation(simulate_failures=True)
    print(f"\nFailure simulation {'succeeded' if success else 'failed'}\n")

if __name__ == "__main__":
    main()