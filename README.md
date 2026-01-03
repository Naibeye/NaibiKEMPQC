# DLPL-Schemes: Post-Quantum PKE and KEM

A post-quantum secure **Public Key Encryption (PKE)** and **Key Encapsulation Mechanism (KEM)** based on the **Discrete Logarithm Problem over Lattices (DLPL-DH)**.

## Overview

This implementation follows the cryptographic scheme described in the paper:
> *"Discrete Logarithm over Lattices (DLPL): A Structured Generalisation with Practical Post-Quantum Applications"*  
> — Djimnaibeye Sidoine, Djiby Sow and Borgou Mahamat

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

# Compile (default: Level 1)
make

# Run PKE tests
./test_dlpl

# Run KEM tests
./test_kem

# Run benchmarks
./test_dlpl --bench
./test_kem --bench
```

## Testing Commands

### C Implementation - Complete Test Suite

#### Compile for Specific Security Level

```bash
cd c_src

# Level 1 (128-bit security, k=2)
make level1

# Level 3 (192-bit security, k=3)
make level3

# Level 5 (256-bit security, k=4)
make level5

# Default (Level 1)
make
```

#### Run All Tests

```bash
# Run PKE tests (keygen, encrypt/decrypt, roundtrip, serialization)
./test_dlpl

# Run KEM tests (keygen, encaps/decaps, roundtrip, serialization)
./test_kem

# Run all tests for all security levels
./test_all_levels.sh
```

#### Benchmark Performance

```bash
# PKE benchmarks (timing for keygen, encrypt, decrypt)
./test_dlpl --bench

# KEM benchmarks (timing for keygen, encaps, decaps)
./test_kem --bench

# Verbose output with details
./test_dlpl --verbose
./test_kem --verbose
```

#### Generate KAT (Known Answer Tests)

```bash
# Compile cavp_gen
make level5  # or any level
cc -Wall -std=c11 -DDLPL_SECURITY_LEVEL=5 -c cavp_gen.c -o cavp_gen.o
cc -DDLPL_SECURITY_LEVEL=5 dlpl_ntt.o dlpl_poly.o dlpl_pke.o dlpl_kem.o cavp_gen.o -o cavp_gen -lm

# Generate all KAT files
./cavp_gen --all --count 100

# Generate only specific KAT files
./cavp_gen --pke --count 50      # PKE KAT only
./cavp_gen --kem --count 50      # KEM KAT only
./cavp_gen --json --count 10     # JSON format only
./cavp_gen --intermediate        # Intermediate values

# Output files:
# - PQCkemKAT_PKE.rsp   (PKE test vectors)
# - PQCkemKAT_KEM.rsp   (KEM test vectors)
# - kat.json            (JSON format)
# - intermediate_values.txt
```

#### Clean Build

```bash
# Remove all compiled objects and executables
make clean

# Full rebuild
make clean && make level1
```

### Python Implementation - Tests

```bash
cd NaibiPQC

# Run all tests (PKE + KEM)
python3 pke_dlpl.py

# Run with specific security level
python3 -c "
from pke_dlpl import DLPL_PKE_Full, DLPL_KEM

# Test PKE
pke = DLPL_PKE_Full.from_security_level('L1')
pk, sk = pke.keygen()
msg = b'Test message'
ct = pke.encrypt(msg)
dec = pke.decrypt(ct)
print(f'PKE: {dec.rstrip(chr(0).encode()) == msg}')

# Test KEM
kem = DLPL_KEM.from_security_level('L1')
pk, sk = kem.keygen()
ct, ss1 = kem.encaps(pk)
ss2 = kem.decaps(ct, sk)
print(f'KEM: {ss1 == ss2}')
"

# Run benchmarks
python3 benchmark_comparison.py
```

### Verify KAT Files

```bash
cd NaibiPQC

# Generate KAT files first (in c_src)
cd c_src && ./cavp_gen --all --count 5 && cd ..

# Verify KAT files
python3 verify_kat.py
```

### Cross-Implementation Verification

```bash
# 1. Generate KAT with C implementation
cd c_src
make level1
./cavp_gen --all --count 10
cd ..

# 2. Verify with Python
python3 verify_kat.py

# Expected output:
# KEM Results: 10 passed, 0 failed
# PKE Results: 10 passed, 0 failed
# JSON: Valid vectors: 10/10
# Intermediate values: All PASS
```

### Test All Security Levels (Automated)

```bash
cd c_src

# Create test script if not exists
cat > run_all_tests.sh << 'EOF'
#!/bin/bash
set -e
echo "=== Testing All Security Levels ==="

for level in 1 3 5; do
    echo ""
    echo "=== Level $level ==="
    make clean
    make level$level
    echo "--- PKE Tests ---"
    ./test_dlpl
    echo "--- KEM Tests ---"
    ./test_kem
    echo "--- Benchmarks ---"
    ./test_dlpl --bench
    ./test_kem --bench
done

echo ""
echo "=== ALL TESTS PASSED ==="
EOF
chmod +x run_all_tests.sh

# Run all tests
./run_all_tests.sh
```

### Memory and Sanitizer Tests

```bash
cd c_src

# Compile with AddressSanitizer (detect memory errors)
make clean
CFLAGS="-fsanitize=address -g" make level1
./test_dlpl
./test_kem

# Compile with UndefinedBehaviorSanitizer
make clean
CFLAGS="-fsanitize=undefined -g" make level1
./test_dlpl
./test_kem

# Valgrind memory check
make clean && make level1
valgrind --leak-check=full ./test_dlpl
valgrind --leak-check=full ./test_kem
```

### Expected Test Output

```
=== DLPL-DH PKE Tests ===
Parameters: n=256, k=2, q=7681
Test 1: NTT roundtrip .............. PASS
Test 2: Polynomial multiplication .. PASS
Test 3: Key generation ............. PASS
Test 4: Encrypt/Decrypt ............ PASS
Test 5: Public key serialization ... PASS
Test 6: Secret key serialization ... PASS
Test 7: Ciphertext serialization ... PASS
Test 8: Zero message ............... PASS
Test 9: Random messages (100x) ..... PASS
=========================================
All 9 tests PASSED!
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

### Unified Parameters (C and Python)

| Level | n | q | k | η_s | η_e | Security |
|-------|-----|------|---|-----|-----|----------|
| **L1** | 256 | 7681 | 2 | 3 | 3 | 128-bit |
| **L3** | 256 | 7681 | 3 | 2 | 2 | 192-bit |
| **L5** | 256 | 7681 | 4 | 2 | 2 | 256-bit |

- **n**: Polynomial degree (power of 2)
- **q**: Prime modulus (NTT-friendly: q ≡ 1 mod 2n)
- **k**: Matrix dimension (block-circulant k×k)
- **η_s, η_e**: CBD (Centered Binomial Distribution) parameters for small elements

### Key and Ciphertext Sizes

| Level | Public Key | Secret Key (KEM) | Ciphertext | Shared Secret |
|-------|------------|------------------|------------|---------------|
| L1 | 3,328 bytes | 5,056 bytes | 1,696 bytes | 32 bytes |
| L3 | 7,488 bytes | 10,048 bytes | 3,776 bytes | 32 bytes |
| L5 | 13,312 bytes | 16,704 bytes | 6,688 bytes | 32 bytes |

*Note: Uses Kyber-style bit-packing (13 bits/coefficient for q=7681) for compact serialization.*

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

### Serialization (Kyber-style Encoding)

Compact bit-packing for polynomial coefficients, reducing storage by ~60-80%.

```python
def get_encoding_bits(q: int) -> int
    """Get number of bits needed to encode coefficients mod q.
    Returns ceil(log2(q)). For q=7681, returns 13 bits."""

def poly_encode(coeffs: np.ndarray, n: int, bits: int) -> bytes
    """Encode polynomial coefficients using bit-packing.
    
    Args:
        coeffs: Array of n coefficients in [0, q-1]
        n: Polynomial degree
        bits: Bits per coefficient (e.g., 13 for q=7681)
    
    Returns:
        Packed bytes of length (n * bits + 7) // 8
    
    Example:
        For n=256, bits=13: 256 coefficients → 416 bytes (vs 512 raw)
    """

def poly_decode(data: bytes, n: int, bits: int) -> np.ndarray
    """Decode bit-packed bytes back to polynomial coefficients.
    
    Args:
        data: Packed bytes from poly_encode
        n: Polynomial degree
        bits: Bits per coefficient
    
    Returns:
        Array of n coefficients
    """

def compress(coeffs: np.ndarray, q: int, d: int) -> np.ndarray
    """Lossy compression of coefficients to d bits (Kyber-style).
    
    Computes: round(2^d / q * x) mod 2^d
    
    Args:
        coeffs: Coefficients in [0, q-1]
        q: Modulus
        d: Target bits (typically 10-12)
    
    Returns:
        Compressed coefficients in [0, 2^d - 1]
    """

def decompress(coeffs: np.ndarray, q: int, d: int) -> np.ndarray
    """Decompress coefficients from d bits back to mod q.
    
    Computes: round(q / 2^d * x)
    
    Args:
        coeffs: Compressed coefficients in [0, 2^d - 1]
        q: Target modulus
        d: Source bits
    
    Returns:
        Decompressed coefficients in [0, q-1]
    """
```

#### Size Comparison

| Encoding | Bytes per Polynomial (n=256) | Reduction |
|----------|------------------------------|-----------|
| Raw int64 | 2,048 bytes | — |
| Raw int16 | 512 bytes | 75% |
| **Kyber-style (13-bit)** | **416 bytes** | **80%** |
| Compressed (10-bit) | 320 bytes | 84% |

#### C Implementation

```c
/* In dlpl_poly.c */

// Encode polynomial to bytes using bit-packing
void poly_to_bytes(uint8_t *out, const poly_t *p);

// Decode polynomial from bit-packed bytes  
void poly_from_bytes(poly_t *p, const uint8_t *in);

// Size macro: (n * LOGQ + 7) / 8 bytes per polynomial
#define DLPL_POLY_BYTES  ((DLPL_N * DLPL_LOGQ + 7) / 8)  // 416 for n=256, q=7681
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

### C Implementation Benchmarks

**PKE Performance:**
| Level | n | k | q | KeyGen | Encrypt | Decrypt |
|-------|-----|---|-------|--------|---------|---------|
| L1 | 256 | 2 | 7681 | 2.21 ms (454 ops/s) | 3.37 ms (297 ops/s) | 2.16 ms (463 ops/s) |
| L3 | 256 | 3 | 7681 | 7.27 ms (138 ops/s) | 12.61 ms (79 ops/s) | 6.14 ms (163 ops/s) |
| L5 | 256 | 4 | 7681 | 14.45 ms (69 ops/s) | 26.42 ms (38 ops/s) | 12.72 ms (79 ops/s) |

**KEM Performance:**
| Level | n | k | q | KeyGen | Encaps | Decaps |
|-------|-----|---|-------|--------|--------|--------|
| L1 | 256 | 2 | 7681 | 3.92 ms (255 ops/s) | 4.02 ms (249 ops/s) | 5.94 ms (168 ops/s) |
| L3 | 256 | 3 | 7681 | 10.42 ms (96 ops/s) | 12.48 ms (80 ops/s) | 22.16 ms (45 ops/s) |
| L5 | 256 | 4 | 7681 | 15.82 ms (63 ops/s) | 26.59 ms (38 ops/s) | 38.43 ms (26 ops/s) |

**Sizes (with Kyber-style bit-packing):**
| Level | Public Key | Secret Key (PKE) | Secret Key (KEM) | Ciphertext | Shared Secret |
|-------|------------|------------------|------------------|------------|---------------|
| L1 | 3,328 bytes | 832 bytes | 5,056 bytes | 1,696 bytes | 32 bytes |
| L3 | 7,488 bytes | 1,248 bytes | 10,048 bytes | 3,776 bytes | 32 bytes |
| L5 | 13,312 bytes | 1,664 bytes | 16,704 bytes | 6,688 bytes | 32 bytes |

### Python Implementation Benchmarks

**PKE Benchmarks** (single-threaded Python, NumPy):

| Level | n | k | KeyGen | Encrypt | Decrypt |
|-------|-----|---|--------|---------|---------|
| toy | 64 | 2 | ~166 ms | ~112 ms | ~18 ms |
| L1 | 256 | 2 | ~261 ms | ~434 ms | ~93 ms |
| L3 | 256 | 3 | ~290 ms | ~465 ms | ~132 ms |
| L5 | 256 | 4 | ~620 ms | ~1216 ms | ~345 ms |

**KEM Benchmarks** (single-threaded Python, NumPy):

| Level | n | k | KeyGen | Encaps | Decaps |
|-------|-----|---|--------|--------|--------|
| L1 | 256 | 2 | ~476 ms | ~281 ms | ~423 ms |
| L3 | 256 | 3 | ~375 ms | ~391 ms | ~471 ms |
| L5 | 256 | 4 | ~850 ms | ~1137 ms | ~1219 ms |

**Python Sizes (with Kyber-style bit-packing):**

| Level | Public Key | Secret Key (KEM) | Ciphertext | Shared Secret |
|-------|------------|------------------|------------|---------------|
| L1 | 3,328 bytes | 5,056 bytes | 1,696 bytes | 32 bytes |
| L3 | 7,488 bytes | 10,048 bytes | 3,776 bytes | 32 bytes |
| L5 | 13,312 bytes | 16,704 bytes | 6,688 bytes | 32 bytes |

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
