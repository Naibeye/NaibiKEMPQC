# DLPL-DH: Post-Quantum PKE and KEM

A post-quantum secure **Public Key Encryption (PKE)** and **Key Encapsulation Mechanism (KEM)** based on the **Discrete Logarithm Problem over Lattices (DLPL-DH)**.

## Overview

This implementation follows the cryptographic scheme described in the paper:
> *"Discrete Logarithm over Lattices (DLPL): A Structured Generalisation with Practical Post-Quantum Applications"*  
> — Djimnaibeye Sidoine

The scheme operates in the commutative algebra $\text{BC}_k(R_q)$ of **block-circulant matrices** over the polynomial ring $R_q = \mathbb{Z}_q[x]/(x^n + 1)$.

## Features

- **Post-Quantum Security**: Based on lattice problems resistant to quantum attacks
- **PKE + KEM**: Complete encryption scheme with IND-CCA2 secure KEM (Fujisaki-Okamoto transform)
- **Multiple Security Levels**: NIST L1 (128-bit), L3 (192-bit), L5 (256-bit)
- **Dual Implementation**: Python (reference) + C (optimized)
- **NTT Acceleration**: Number Theoretic Transform for $O(n \log n)$ polynomial multiplication
- **Side-Channel Protection**: Constant-time operations, masking, blinding
- **Barrett/Montgomery Reduction**: Constant-time modular arithmetic

## Installation

### Python Implementation

```bash
# Clone or download the repository
cd NaibiPQC

# Install dependencies
pip install numpy

# Run tests
python3 pke_dlpl.py
```

### C Implementation

```bash
cd c_src

# Compile
make

# Run PKE tests
./test_dlpl

# Run KEM tests
./test_kem

# Run benchmarks
./test_dlpl --bench
./test_kem --bench
```

## Quick Start

### Python - PKE

```python
from pke_dlpl import DLPL_PKE_Full

# Create PKE instance with NIST Level 1 security
pke = DLPL_PKE_Full.from_security_level("L1")

# Generate keys
public_key, secret_key = pke.keygen()

# Encrypt a message (max 32 bytes)
message = b"Hello, Post-Quantum World!"
ciphertext = pke.encrypt(message)

# Decrypt
decrypted = pke.decrypt(ciphertext)
print(decrypted.rstrip(b'\x00'))  # b'Hello, Post-Quantum World!'
```

### Python - KEM

```python
from pke_dlpl import DLPL_KEM

# Create KEM instance
kem = DLPL_KEM.from_security_level("L1")

# Key generation
pk, sk = kem.keygen()

# Encapsulation (sender)
ct, ss_sender = kem.encaps(pk)

# Decapsulation (receiver)
ss_receiver = kem.decaps(ct, sk)

# Both parties now share the same 32-byte secret
assert ss_sender == ss_receiver
```

### C - PKE

```c
#include "dlpl_pke.h"

// Generate keys
public_key_t pk;
secret_key_t sk;
dlpl_keygen(&pk, &sk);

// Encrypt
uint8_t msg[32] = "Hello!";
ciphertext_t ct;
dlpl_encrypt(&ct, &pk, msg);

// Decrypt
uint8_t decrypted[32];
dlpl_decrypt(decrypted, &ct, &sk);
```

### C - KEM

```c
#include "dlpl_kem.h"

// Key generation
kem_public_key_t pk;
kem_secret_key_t sk;
dlpl_kem_keygen(&pk, &sk);

// Encapsulation
kem_ciphertext_t ct;
uint8_t ss_sender[32];
dlpl_kem_encaps(&ct, ss_sender, &pk);

// Decapsulation
uint8_t ss_receiver[32];
dlpl_kem_decaps(ss_receiver, &ct, &sk);
// ss_sender == ss_receiver
```

## Security Levels & Parameters

### Current Parameters (C Implementation)

| Level | n | q | k | η_s | η_e | Security |
|-------|-----|------|---|-----|-----|----------|
| **L1** | 128 | 3329 | 2 | 3 | 3 | 128-bit |
| **L3** | 128 | 3329 | 3 | 2 | 2 | 192-bit |
| **L5** | 128 | 3329 | 4 | 2 | 2 | 256-bit |

- **n**: Polynomial degree (power of 2)
- **q**: Prime modulus (q = 3329, Kyber prime, q ≡ 1 mod 256)
- **k**: Matrix dimension (block-circulant k×k)
- **η_s, η_e**: CBD (Centered Binomial Distribution) parameters for small elements

### Key and Ciphertext Sizes

| Level | Public Key | Secret Key | Ciphertext | Shared Secret |
|-------|------------|------------|------------|---------------|
| L1 | ~2 KB | ~1 KB | ~1 KB | 32 bytes |
| L3 | ~4.5 KB | ~2.3 KB | ~2.3 KB | 32 bytes |
| L5 | ~8 KB | ~4 KB | ~4 KB | 32 bytes |

## API Reference

### Core Classes

#### `DLPL_PKE_Full`

High-level PKE interface with key storage.

```python
class DLPL_PKE_Full:
    def __init__(self, security_level: str = None, n: int = None, 
                 q: int = None, k: int = None, eta_s: int = None, 
                 eta_e: int = None)
    
    @classmethod
    def from_security_level(cls, level: str) -> 'DLPL_PKE_Full'
        """Create instance from NIST security level ('L1', 'L3', 'L5', 'toy')."""
    
    def keygen(self) -> Tuple[PublicKey, SecretKey]
        """Generate public and secret keys."""
    
    def encrypt(self, message: bytes) -> Ciphertext
        """Encrypt a message (max 32 bytes)."""
    
    def decrypt(self, ciphertext: Ciphertext) -> bytes
        """Decrypt a ciphertext."""
    
    def decrypt_with_verification(self, ciphertext: Ciphertext) -> Tuple[bytes, bool]
        """Decrypt with FO-transform verification for CCA2 security."""
    
    def get_key_sizes(self) -> dict
        """Return key and ciphertext sizes in bytes."""
```

#### `RingElement`

Element of $R_q = \mathbb{Z}_q[x]/(x^n + 1)$.

```python
class RingElement:
    use_ntt: bool = False  # Enable NTT multiplication
    enable_sidechannel_protection: bool = True
    
    def __init__(self, coeffs: np.ndarray, n: int, q: int, ntt_form: bool = False)
    
    # Arithmetic operations
    def __add__(self, other) -> RingElement
    def __sub__(self, other) -> RingElement
    def __mul__(self, other) -> RingElement
    def __neg__(self) -> RingElement
    
    # NTT conversion
    def to_ntt(self) -> RingElement
    def from_ntt(self) -> RingElement
    
    # Inversion
    def inverse(self) -> Optional[RingElement]
    
    # Utilities
    def norm_inf(self) -> int
    def to_bytes(self) -> bytes
    
    @classmethod
    def zero(cls, n: int, q: int) -> RingElement
    @classmethod
    def one(cls, n: int, q: int) -> RingElement
```

#### `BlockCirculantMatrix`

Element of $\text{BC}_k(R_q)$ - block-circulant matrices.

```python
class BlockCirculantMatrix:
    enable_sidechannel_protection: bool = True
    
    def __init__(self, first_row: List[RingElement], n: int, q: int, k: int)
    
    def get_block(self, i: int, j: int) -> RingElement
    
    # Arithmetic (stays in BC_k)
    def __add__(self, other) -> BlockCirculantMatrix
    def __sub__(self, other) -> BlockCirculantMatrix
    def __mul__(self, other) -> BlockCirculantMatrix | GeneralMatrix
    
    # Inversion with optional blinding
    def inverse(self, use_blinding: bool = None) -> Optional[BlockCirculantMatrix]
    
    @classmethod
    def zero(cls, n, q, k) -> BlockCirculantMatrix
    @classmethod
    def identity(cls, n, q, k) -> BlockCirculantMatrix
```

#### `GeneralMatrix`

General $k \times k$ matrix over $R_q$ (for public parameter A).

```python
class GeneralMatrix:
    def __init__(self, blocks: List[RingElement], n: int, q: int, k: int)
    
    def get_block(self, i: int, j: int) -> RingElement
    def set_block(self, i: int, j: int, val: RingElement)
    
    # Arithmetic
    def __add__(self, other) -> GeneralMatrix
    def __sub__(self, other) -> GeneralMatrix
    def __mul__(self, other) -> GeneralMatrix
    
    @classmethod
    def random(cls, n, q, k) -> GeneralMatrix
    @classmethod
    def identity(cls, n, q, k) -> GeneralMatrix
```

### Number Theoretic Transform

#### `NTT`

Fast polynomial multiplication using negacyclic NTT.

```python
class NTT:
    def __init__(self, n: int, q: int)
        """Initialize NTT. Requires q ≡ 1 (mod 2n)."""
    
    def forward(self, a: np.ndarray) -> np.ndarray
        """Compute forward NTT: coefficients → NTT domain."""
    
    def inverse(self, a_hat: np.ndarray) -> np.ndarray
        """Compute inverse NTT: NTT domain → coefficients."""
    
    def multiply(self, a: np.ndarray, b: np.ndarray) -> np.ndarray
        """Multiply two polynomials using NTT."""

def get_ntt(n: int, q: int) -> NTT
    """Get cached NTT instance for given parameters."""
```

### Side-Channel Protection

#### `BarrettReducer`

Constant-time modular reduction without division.

```python
class BarrettReducer:
    def __init__(self, q: int, k: int = None)
    
    def reduce(self, x: int) -> int
        """Compute x mod q in constant time."""
    
    def reduce_array(self, arr: np.ndarray) -> np.ndarray
        """Vectorized Barrett reduction."""
```

#### `MontgomeryReducer`

Montgomery multiplication for constant-time modular arithmetic.

```python
class MontgomeryReducer:
    def __init__(self, q: int, k: int = None)
        """Initialize for odd modulus q."""
    
    def to_montgomery(self, x: int) -> int
        """Convert x to Montgomery domain: xR mod q."""
    
    def from_montgomery(self, x_mont: int) -> int
        """Convert from Montgomery domain."""
    
    def multiply(self, a_mont: int, b_mont: int) -> int
        """Montgomery multiplication: (aR * bR) → abR mod q."""
```

#### `SideChannelProtection`

Utilities for side-channel attack mitigation.

```python
class SideChannelProtection:
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool
        """Constant-time byte comparison."""
    
    @staticmethod
    def constant_time_select(condition: bool, a: int, b: int) -> int
        """Branch-free conditional selection."""
    
    @staticmethod
    def secure_zero(arr: np.ndarray) -> None
        """Securely zero sensitive data."""
    
    @staticmethod
    def generate_mask(n: int, q: int) -> np.ndarray
        """Generate random blinding mask."""
    
    @classmethod
    def constant_time_mod(cls, x: int, q: int) -> int
        """Constant-time modular reduction (Barrett)."""
    
    @classmethod
    def constant_time_mul_mod(cls, a: int, b: int, q: int) -> int
        """Constant-time modular multiplication (Montgomery/Barrett)."""
    
    @staticmethod
    def validate_range(coeffs: np.ndarray, q: int) -> bool
        """Validate coefficient ranges."""
```

### Polynomial Arithmetic

```python
def poly_extended_gcd(a: np.ndarray, b: np.ndarray, q: int) 
    -> Tuple[np.ndarray, np.ndarray, np.ndarray]
    """Extended Euclidean Algorithm for polynomials over Z_q.
    Returns (gcd, s, t) such that gcd = s*a + t*b."""

def poly_inverse_mod(a: np.ndarray, n: int, q: int) -> Optional[np.ndarray]
    """Compute inverse of polynomial a in R_q = Z_q[x]/(x^n + 1)."""
```

## Mathematical Background

### Ring Structure

The scheme works over:
- **Base ring**: $R_q = \mathbb{Z}_q[x]/(x^n + 1)$ where $n$ is a power of 2
- **Matrix algebra**: $\text{BC}_k(R_q)$ — $k \times k$ block-circulant matrices over $R_q$

A block-circulant matrix is determined by its first row $[A_0, A_1, \ldots, A_{k-1}]$:

$$\text{BC}([A_0, \ldots, A_{k-1}]) = \begin{pmatrix} A_0 & A_1 & \cdots & A_{k-1} \\ A_{k-1} & A_0 & \cdots & A_{k-2} \\ \vdots & & \ddots & \vdots \\ A_1 & A_2 & \cdots & A_0 \end{pmatrix}$$

**Key property**: $\text{BC}_k(R_q)$ is a **commutative ring** — matrix multiplication is commutative within this subset.

### DLPL-DH PKE Scheme

#### Key Generation
```
Input: Security parameters (n, q, k, η_s, η_e)
Output: Public key pk = (A, t), Secret key sk = (s, e)

1. Sample A ←$ R_q^{k×k}           (general k×k matrix, NOT block-circulant)
2. Sample s ←$ BC_k(R_q)           (small invertible block-circulant, CBD(η_s))
3. Sample e ←$ BC_k(R_q)           (small block-circulant, CBD(η_e))
4. Compute t = (s·A + e)·s⁻¹
5. Return pk = (A, t), sk = (s, e)
```

#### Encryption
```
Input: Public key pk = (A, t), Message m ∈ {0,1}^256
Output: Ciphertext ct = (u, v)

1. Derive (r, d) = G(pk, m)        (r invertible, d small, via hash function)
2. Compute u = (r·A + d)·r⁻¹
3. Compute shared = (r·t + d)·r⁻¹
4. Compute v = m ⊕ H(shared)
5. Return ct = (u, v)
```

#### Decryption
```
Input: Secret key sk = (s, e), Ciphertext ct = (u, v)
Output: Message m

1. Compute shared = (s·u + e)·s⁻¹
2. Compute m = v ⊕ H(shared)
3. Return m
```

#### Correctness
The decryption works because:
$$
(s \cdot u + e) \cdot s^{-1} = (s \cdot (r \cdot A + d) \cdot r^{-1} + e) \cdot s^{-1}
$$
$$
= ((s \cdot r \cdot A + s \cdot d) \cdot r^{-1} + e) \cdot s^{-1}
$$

Using commutativity in $\text{BC}_k(R_q)$:
$$
= (r \cdot t + d) \cdot r^{-1} = \text{shared}
$$

### DLPL-DH KEM (Fujisaki-Okamoto Transform)

The KEM provides **IND-CCA2** security by applying the FO transform to the PKE:

#### Key Generation
```
1. (pk_pke, sk_pke) ← PKE.KeyGen()
2. z ←$ {0,1}^256                  (implicit rejection secret)
3. pk = pk_pke
4. sk = (sk_pke, pk_pke, z)
5. Return (pk, sk)
```

#### Encapsulation
```
Input: Public key pk
Output: Ciphertext ct, Shared secret K

1. Sample m ←$ {0,1}^256
2. K = H(m || pk)                  (derive key from message)
3. ct = PKE.Encrypt(pk, m)         (deterministic via hash_G)
4. K' = H(K || ct)                 (final shared secret)
5. Return (ct, K')
```

#### Decapsulation
```
Input: Secret key sk = (sk_pke, pk_pke, z), Ciphertext ct
Output: Shared secret K

1. m' = PKE.Decrypt(sk_pke, ct)
2. K = H(m' || pk)
3. ct' = PKE.Encrypt(pk, m')       (re-encrypt)
4. If ct == ct':
     Return K' = H(K || ct)        (valid)
   Else:
     Return K' = H(z || ct)        (implicit rejection)
```

### Security Assumptions

The scheme's security relies on:

1. **DLPL Assumption**: Given $(A, t = (sA + e)s^{-1})$, it's hard to recover $s$ or distinguish from random.

2. **Module-LWE Connection**: The DLPL problem relates to Module-LWE with structured secrets.

3. **Hardness Parameters**: 
   - Small secrets ($\|s\|_\infty, \|e\|_\infty \leq \eta$)
   - Ring structure $R_q = \mathbb{Z}_q[x]/(x^n+1)$ provides algebraic hardness

## Side-Channel Countermeasures

### Constant-Time Operations

All secret-dependent operations use constant-time algorithms:
- **Barrett reduction**: $x \mod q$ without division
- **Montgomery multiplication**: Modular multiplication without division
- **Comparison**: Timing-independent byte comparison
- **Selection**: Branch-free conditional selection

### Blinding

Secret key operations use multiplicative blinding:
```
s^{-1} = ((s · r)^{-1}) · r
```
where $r$ is a random invertible element.

### Memory Protection

- Sensitive data is securely zeroed after use
- Input validation prevents fault injection attacks

## Performance

Benchmarks on typical hardware (single-threaded Python):

| Level | KeyGen | Encrypt | Decrypt |
|-------|--------|---------|---------|
| toy | ~40 ms | ~60 ms | ~25 ms |
| L1 | ~240 ms | ~370 ms | ~140 ms |

Note: Performance can be improved 10-100x with:
- C/Rust implementation
- AVX2/AVX-512 vectorization
- Optimized NTT with precomputation

## File Structure

```
NaibiPQC/
├── pke_dlpl.py          # Python implementation (PKE + KEM)
├── README.md            # This documentation
├── mainpaper.tex        # Reference paper (LaTeX)
└── c_src/               # C implementation
    ├── dlpl_params.h    # Parameter definitions
    ├── dlpl_ntt.h/c     # Number Theoretic Transform
    ├── dlpl_poly.h/c    # Polynomial & matrix operations
    ├── dlpl_pke.h/c     # PKE implementation
    ├── dlpl_kem.h/c     # KEM implementation (FO transform)
    ├── test_dlpl.c      # PKE test suite
    ├── test_kem.c       # KEM test suite
    └── Makefile         # Build system
```

## Testing

### Python Tests

```bash
python3 pke_dlpl.py
```

Tests include:
- Side-channel protection (Barrett, Montgomery, constant-time ops)
- NTT correctness (forward/inverse, multiplication)
- Polynomial inversion (extended GCD)
- PKE correctness (encrypt/decrypt round-trip)
- KEM correctness (encaps/decaps)
- All security levels

### C Tests

```bash
cd c_src
make
./test_dlpl      # PKE: 9 tests
./test_kem       # KEM: 5 tests
```

**PKE Tests**:
- NTT roundtrip
- Polynomial multiplication via NTT
- Block-circulant matrix inverse
- Key generation
- Encrypt/Decrypt
- Multiple encrypt/decrypt
- Decrypt with verification
- Serialization
- Constant-time compare

**KEM Tests**:
- Basic encaps/decaps
- Multiple KEM operations
- Implicit rejection (tampered ciphertext)
- Serialization roundtrip
- Deterministic encapsulation

## License

Research implementation — see paper for licensing terms.

## References

1. Djimnaibeye Sidoine, *"Discrete Logarithm over Lattices (DLPL): A Structured Generalisation with Practical Post-Quantum Applications"*
2. NIST Post-Quantum Cryptography Standardization
3. Kyber/ML-KEM specification (NTT, parameters q=3329)
4. Fujisaki-Okamoto Transform for IND-CCA2 security

## Author

**Djimnaibeye Sidoine**
