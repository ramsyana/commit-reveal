# Commit-Reveal²

A secure and efficient implementation of a two-phase commit-reveal protocol for distributed consensus applications.

## Overview

Commit-Reveal² is a protocol implementation that enables participants to make verifiable commitments and reveals in a distributed system. The protocol operates in two phases:

1. **Commitment Phase (Phase 0)**: Participants generate and commit to secret values using cryptographic primitives
2. **Reveal Phase**: Participants reveal their commitments and verify others' reveals

## Features

- Secure cryptographic primitives (Keccak-256 hashing, ECDSA signatures)
- Deterministic commitment chain generation
- Participant identity management
- Leader-based communication simulation
- Comprehensive test coverage

## Installation

```bash
# Clone the repository
git clone [repository-url]
cd commit-reveal

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Example

```python
from src.participant import Participant

# Initialize a participant
participant = Participant("participant_1")

# Generate commitment chain
participant.generate_commitments()

# Sign and send data to leader
data = b"example data"
data, signature = participant.send_to_leader(data, "phase0")
```

## Components

### Cryptographic Utilities

- **Hash Function**: Keccak-256 implementation for commitment generation
- **Key Management**: ECDSA keypair generation and Ethereum-style address derivation
- **Signatures**: Message signing and verification

### Participant

The `Participant` class manages:
- Identity and key material
- Commitment chain generation
- Leader communication
- Data signing

## Development

### Testing

The project uses pytest for testing. Run the test suite:

```bash
python -m pytest tests/
```

Phase 0 tests cover:
- Cryptographic utility functions
- Participant initialization and operations
- Commitment chain verification
- Leader communication simulation

### Project Structure

```
commit-reveal/
├── src/
│   ├── crypto_utils.py   # Cryptographic primitives
│   └── participant.py    # Participant implementation
├── tests/
│   └── test_phase0.py   # Phase 0 test suite
└── requirements.txt      # Project dependencies
```

## Contributing

Contributions are welcome! Please ensure:
1. Tests pass and coverage is maintained
2. Code follows project style and conventions
3. Documentation is updated for significant changes

## License

[License details to be added]