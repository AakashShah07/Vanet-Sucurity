# VANET Security Prototype

A proof-of-concept implementation of secure message passing in Vehicular Ad-Hoc Networks (VANETs) using digital signatures and hash functions.


### Final Time Allocation
| Task | Time |
|------|------|
| Setup & Environment | 30m |
| Core Vehicle Class | 1h |
| Network Simulation | 2h |
| Demo Script | 1h |
| Testing & Debugging | 1h |
| Documentation | 2h |
| **Total** | **7.5h** |

This gives you time for breaks and final adjustments. The implementation demonstrates all key security aspects while being achievable in a single day.

## Features
- Vehicle-to-vehicle secure communication
- Digital signatures for authentication
- SHA-256 hashing for message integrity
- Attack simulations:
  - Message tampering detection
  - Impersonation attempt detection

## How It Works
1. Each vehicle has RSA public/private key pair
2. Messages are hashed and signed by sender
3. Recipients verify both hash and signature
4. Any modification invalidates the message

## Running the Demo
```bash
pip install cryptography
python demo.py