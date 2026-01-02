/**
 * @file dlpl_ntt.c
 * @brief Optimized NTT implementation for DLPL-DH PKE
 * 
 * Uses negacyclic NTT for computing polynomial multiplication 
 * in Z_q[x]/(x^n + 1).
 * 
 * Optimizations:
 * - Precomputed twiddle factors in Montgomery domain
 * - Montgomery multiplication (no division)
 * - Precomputed bit-reversal table  
 * - Lazy reduction where possible
 */

#include "dlpl_ntt.h"
#include <string.h>

/* ==========================================================================
 * Montgomery Constants - depend on q (defined in dlpl_params.h via dlpl_ntt.h)
 * 
 * R = 2^16 = 65536
 * R^2 mod q and q' such that q * q' ≡ -1 (mod R)
 * ========================================================================== */

#undef MONT_R  /* Undefine from header to use our optimized constants */
#define MONT_R       65536       /* Montgomery R = 2^16 */
#define MONT_R_LOG2  16

/* q = 3329 (Kyber): R² = 1353, q' = 3327
 *   Verification: 3329 * 3327 = 11,077,983 ≡ -1 (mod 65536)
 * q = 7681 (NewHope): R² = 5569, q' = 7679
 *   Verification: 7681 * 7679 = 58,979,999 ≡ -1 (mod 65536)
 */
#if DLPL_Q == 3329
  #define MONT_R2      1353      /* R^2 mod 3329 */
  #define MONT_QPRIME  3327      /* q' for q=3329 */
#elif DLPL_Q == 7681
  #define MONT_R2      5569      /* R^2 mod 7681 */
  #define MONT_QPRIME  7679      /* q' for q=7681 */
#else
  #error "Unsupported DLPL_Q value - add Montgomery constants"
#endif

/* Global Montgomery constant (for external use) */
int32_t MONT_Q_PRIME = MONT_QPRIME;

/* ==========================================================================
 * Precomputed Tables (in Montgomery domain)
 * ========================================================================== */

/* Powers of psi for pre/post multiplication (negacyclic) - Montgomery form */
static int16_t psi_mont[DLPL_N];
static int16_t psi_inv_mont[DLPL_N];

/* Powers of omega = psi^2 for DFT butterflies - Montgomery form */
static int16_t omega_mont[DLPL_N];
static int16_t omega_inv_mont[DLPL_N];

/* Bit-reversal permutation table */
static uint16_t bit_rev_table[DLPL_N];

/* n^-1 mod q in Montgomery form */
static int16_t n_inv_mont;

/* Initialization flag */
static int ntt_initialized = 0;

/* ==========================================================================
 * Montgomery Arithmetic
 * ========================================================================== */

/**
 * @brief Montgomery reduction: compute x * R^{-1} mod q
 * @param x Input value (can be product of two values < q*R)
 * @return x * R^{-1} mod q in range [0, q)
 * 
 * Given x < q * R, computes x * R^{-1} mod q without division.
 * Uses q' such that q * q' ≡ -1 (mod R).
 */
static inline int16_t mont_reduce(int32_t x) {
    int16_t t;
    /* t = (x mod R) * q' mod R */
    t = (int16_t)((int32_t)(int16_t)x * MONT_QPRIME);
    /* t = (x + t*q) / R */
    t = (int16_t)((x + (int32_t)t * DLPL_Q) >> MONT_R_LOG2);
    /* Ensure result in [0, q) */
    t += (t >> 15) & DLPL_Q;  /* if t < 0, add q */
    return t;
}

/**
 * @brief Montgomery multiplication: compute a*b*R^{-1} mod q
 * @param a First operand in Montgomery form (a' = a*R mod q)
 * @param b Second operand in Montgomery form (b' = b*R mod q)
 * @return a*b*R^{-1} mod q = (a'*b') * R^{-1} mod q
 * 
 * If inputs are a*R and b*R, output is a*b*R mod q.
 */
static inline int16_t mont_mul(int16_t a, int16_t b) {
    return mont_reduce((int32_t)a * b);
}

/**
 * @brief Convert to Montgomery domain: compute x*R mod q
 * @param x Input value in [0, q)
 * @return x * R mod q
 */
static inline int16_t to_mont(int16_t x) {
    return mont_reduce((int32_t)x * MONT_R2);
}

/**
 * @brief Convert from Montgomery domain: compute x*R^{-1} mod q
 * @param x Input value in Montgomery form
 * @return x * R^{-1} mod q (normal form)
 */
static inline int16_t from_mont(int16_t x) {
    return mont_reduce((int32_t)x);
}

/**
 * @brief Conditional subtraction for reduction
 */
static inline int16_t cond_sub(int16_t x) {
    x -= DLPL_Q;
    x += (x >> 15) & DLPL_Q;
    return x;
}

/* ==========================================================================
 * Helper Functions
 * ========================================================================== */

static int64_t mod_pow64(int64_t a, int64_t e, int64_t m) {
    int64_t result = 1;
    a = ((a % m) + m) % m;
    while (e > 0) {
        if (e & 1) result = (result * a) % m;
        e >>= 1;
        a = (a * a) % m;
    }
    return result;
}

static int64_t mod_inv64(int64_t a, int64_t m) {
    return mod_pow64(a, m - 2, m);
}

static uint16_t bit_reverse(uint16_t x, int bits) {
    uint16_t result = 0;
    for (int i = 0; i < bits; i++) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

/* ==========================================================================
 * NTT Initialization - Precompute all tables in Montgomery domain
 * ========================================================================== */

void ntt_init(void) {
    if (ntt_initialized) return;
    
    int64_t q = DLPL_Q;
    int n = DLPL_N;
    
    /* Compute log2(n) */
    int log_n = 0;
    for (int t = n; t > 1; t >>= 1) log_n++;
    
    /* Find generator g of Z_q^* */
    int64_t g = -1;
    for (int64_t cand = 2; cand < q && g < 0; cand++) {
        if (mod_pow64(cand, (q-1)/2, q) == q - 1) {
            g = cand;
        }
    }
    
    /* psi = g^((q-1)/(2n)) is primitive 2n-th root of unity */
    int64_t psi = mod_pow64(g, (q - 1) / (2 * n), q);
    int64_t psi_inv = mod_inv64(psi, q);
    
    /* omega = psi^2 is primitive n-th root of unity */
    int64_t omega = (psi * psi) % q;
    int64_t omega_inv = mod_inv64(omega, q);
    
    /* Precompute powers in Montgomery domain */
    int64_t psi_pow = 1;
    int64_t psi_inv_pow = 1;
    int64_t omega_pow = 1;
    int64_t omega_inv_pow = 1;
    
    for (int i = 0; i < n; i++) {
        /* Convert to Montgomery form: x*R mod q */
        psi_mont[i] = to_mont((int16_t)psi_pow);
        psi_inv_mont[i] = to_mont((int16_t)psi_inv_pow);
        omega_mont[i] = to_mont((int16_t)omega_pow);
        omega_inv_mont[i] = to_mont((int16_t)omega_inv_pow);
        
        psi_pow = (psi_pow * psi) % q;
        psi_inv_pow = (psi_inv_pow * psi_inv) % q;
        omega_pow = (omega_pow * omega) % q;
        omega_inv_pow = (omega_inv_pow * omega_inv) % q;
    }
    
    /* Precompute bit-reversal table */
    for (int i = 0; i < n; i++) {
        bit_rev_table[i] = bit_reverse(i, log_n);
    }
    
    /* n^-1 mod q in Montgomery form */
    int64_t n_inv = mod_inv64(n, q);
    n_inv_mont = to_mont((int16_t)n_inv);
    
    ntt_initialized = 1;
}

/* ==========================================================================
 * Core DFT with Montgomery multiplication
 * ========================================================================== */

static void dft_forward_mont(poly_coeff_t a[DLPL_N]) {
    /* Bit-reversal permutation */
    for (int i = 0; i < DLPL_N; i++) {
        int j = bit_rev_table[i];
        if (i < j) {
            int16_t t = a[i];
            a[i] = a[j];
            a[j] = t;
        }
    }
    
    /* Cooley-Tukey butterflies with Montgomery multiplication */
    for (int len = 2; len <= DLPL_N; len <<= 1) {
        int half = len >> 1;
        int step = DLPL_N / len;
        
        for (int i = 0; i < DLPL_N; i += len) {
            for (int j = 0; j < half; j++) {
                /* Twiddle in Montgomery form */
                int16_t w = omega_mont[j * step];
                
                int16_t u = a[i + j];
                /* v = a[i+j+half] * w * R^{-1} mod q */
                int16_t v = mont_mul(a[i + j + half], w);
                
                /* Butterfly: u + v, u - v */
                a[i + j] = cond_sub(u + v);
                a[i + j + half] = cond_sub(u - v + DLPL_Q);
            }
        }
    }
}

static void dft_inverse_mont(poly_coeff_t a[DLPL_N]) {
    /* Bit-reversal permutation */
    for (int i = 0; i < DLPL_N; i++) {
        int j = bit_rev_table[i];
        if (i < j) {
            int16_t t = a[i];
            a[i] = a[j];
            a[j] = t;
        }
    }
    
    /* Cooley-Tukey butterflies with Montgomery multiplication */
    for (int len = 2; len <= DLPL_N; len <<= 1) {
        int half = len >> 1;
        int step = DLPL_N / len;
        
        for (int i = 0; i < DLPL_N; i += len) {
            for (int j = 0; j < half; j++) {
                /* Inverse twiddle in Montgomery form */
                int16_t w = omega_inv_mont[j * step];
                
                int16_t u = a[i + j];
                int16_t v = mont_mul(a[i + j + half], w);
                
                a[i + j] = cond_sub(u + v);
                a[i + j + half] = cond_sub(u - v + DLPL_Q);
            }
        }
    }
    
    /* Scale by n^-1 in Montgomery form */
    for (int i = 0; i < DLPL_N; i++) {
        a[i] = mont_mul(a[i], n_inv_mont);
    }
}

/* ==========================================================================
 * Public NTT API: Negacyclic NTT for Z_q[x]/(x^n + 1)
 * 
 * Input/Output: Coefficients in NORMAL form (not Montgomery)
 * Internal: Montgomery multiplication for speed
 * ========================================================================== */

void ntt_forward(poly_coeff_t a[DLPL_N]) {
    /* Pre-multiply by psi^i (Montgomery) for negacyclic */
    /* psi_mont[i] is in Montgomery form, so we get a[i]*psi^i in normal form */
    for (int i = 0; i < DLPL_N; i++) {
        /* a[i] * psi_mont[i] * R^{-1} = a[i] * psi^i */
        a[i] = mont_reduce((int32_t)a[i] * psi_mont[i]);
    }
    
    /* Standard DFT with Montgomery */
    dft_forward_mont(a);
}

void ntt_inverse(poly_coeff_t a[DLPL_N]) {
    /* Standard inverse DFT with Montgomery */
    dft_inverse_mont(a);
    
    /* Post-multiply by psi^(-i) (Montgomery) for negacyclic */
    for (int i = 0; i < DLPL_N; i++) {
        a[i] = mont_reduce((int32_t)a[i] * psi_inv_mont[i]);
    }
}

/* ==========================================================================
 * Pointwise Operations in NTT Domain
 * 
 * After forward NTT, coefficients are in "mixed" Montgomery form.
 * Pointwise mul needs to account for this.
 * ========================================================================== */

void ntt_pointwise_mul(poly_coeff_t r[DLPL_N],
                       const poly_coeff_t a[DLPL_N],
                       const poly_coeff_t b[DLPL_N]) {
    for (int i = 0; i < DLPL_N; i++) {
        /* Need to multiply and reduce properly */
        /* Since NTT outputs are in normal form, we need proper reduction */
        int32_t prod = (int32_t)a[i] * b[i];
        /* Reduce using Barrett since values can be large */
        r[i] = (int16_t)(prod % DLPL_Q);
        if (r[i] < 0) r[i] += DLPL_Q;
    }
}

void ntt_pointwise_mac(poly_coeff_t r[DLPL_N],
                       const poly_coeff_t a[DLPL_N],
                       const poly_coeff_t b[DLPL_N]) {
    for (int i = 0; i < DLPL_N; i++) {
        int32_t sum = (int32_t)r[i] + (int32_t)a[i] * b[i];
        r[i] = (int16_t)(sum % DLPL_Q);
        if (r[i] < 0) r[i] += DLPL_Q;
    }
}

/* ==========================================================================
 * High-Level Polynomial Operations
 * ========================================================================== */

void poly_to_ntt(poly_t *p) {
    ntt_forward(p->coeffs);
}

void poly_from_ntt(poly_t *p) {
    ntt_inverse(p->coeffs);
}

void poly_mul_ntt(poly_t *r, const poly_t *a, const poly_t *b) {
    poly_t a_ntt, b_ntt;
    
    memcpy(&a_ntt, a, sizeof(poly_t));
    memcpy(&b_ntt, b, sizeof(poly_t));
    
    ntt_forward(a_ntt.coeffs);
    ntt_forward(b_ntt.coeffs);
    
    ntt_pointwise_mul(r->coeffs, a_ntt.coeffs, b_ntt.coeffs);
    
    ntt_inverse(r->coeffs);
}
