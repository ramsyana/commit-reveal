# Commit-Reveal²

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![arXiv](https://img.shields.io/badge/arXiv-2504.03936-b31b1b.svg)](https://arxiv.org/abs/2504.03936)

An implementation of "Commit-Reveal²: Randomized Reveal Order Mitigates Last-Revealer Attacks" protocol for distributed consensus applications, following the specifications from Lee et al. (2025).

### Key Features
- Two-layer Commit-Reveal² protocol preventing last-revealer attacks
- Secure cryptographic primitives (Keccak-256 hashing, ECDSA signatures)
- Randomized reveal order generation
- Hybrid on-chain/off-chain architecture
- Deterministic commitment chain generation
- Participant identity management
- Leader-based communication simulation
- Comprehensive test coverage

## Requirements

* Python (>= 3.10 recommended)
* ecdsa==0.18.0
* pysha3==1.0.2
* merkletools==1.0.3
* pytest==7.4.3

A `requirements.txt` file is included for easy installation of dependencies.

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/ramsyana/commit-reveal
    cd commit-reveal
    ```

2. **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```

## Testing

This project uses `pytest` for unit testing. To run the tests:

1. Make sure you are in the root directory of the project (where the `pytest.ini` or `pyproject.toml` file would be, or just the main project folder).
2. Ensure your virtual environment is activated.
3. Run the following command:
   ```bash
   pytest
   ```
   Or for more detailed output:
   ```bash
   pytest -v
   ```

## License

This project is licensed under the MIT License.

```text
MIT License

Copyright (c) 2025 [Ramsyana/ramsyana.com - ramsyana[at]mac.com]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Collaboration & Contribution

Contributions are welcome! Please ensure:
1. Tests pass and coverage is maintained
2. Code follows project style and conventions
3. Documentation is updated for significant changes

## Contact

Contact maintainers at: ramsyana[at]mac.com

If you're interested in collaborating on the protocol or related research, please don't hesitate to reach out.