/**
 * @file dlpl_ntt.h
 * @brief Number Theoretic Transform for fast polynomial multiplication
 * 
 * Implements negacyclic NTT for R_q = Z_q[x]/(x^n + 1)
 * Uses Cooley-Tukey (forward) and Gentleman-Sande (inverse) butterflies
 */

#ifndef DLPL_NTT_H
#define DLPL_NTT_H

#include "dlpl_params.h"

/* ==========================================================================
 * NTT Precomputed Tables
 * ========================================================================== */

/**
 * @brief Initialize NTT tables (call once at startup)
 * 
 * Precomputes:
 * - Twiddle factors (powers of primitive root)
 * - Inverse twiddle factors
 * - Bit-reversal permutation
 * - Barrett reduction constants
 */
void ntt_init(void);

/* ==========================================================================
 * Core NTT Operations
 * ========================================================================== */

/**
 * @brief Forward NTT (Cooley-Tukey, in-place)
 * @param a Polynomial coefficients (modified in place)
 * 
 * Transforms from coefficient domain to NTT domain.
 * After NTT, point-wise multiplication computes polynomial product.
 */
void ntt_forward(poly_coeff_t a[DLPL_N]);

/**
 * @brief Inverse NTT (Gentleman-Sande, in-place)
 * @param a NTT coefficients (modified in place)
 * 
 * Transforms from NTT domain back to coefficient domain.
 * Includes scaling by n^(-1).
 */
void ntt_inverse(poly_coeff_t a[DLPL_N]);

/**
 * @brief Point-wise multiplication in NTT domain
 * @param r Result (can be same as a or b)
 * @param a First operand (NTT domain)
 * @param b Second operand (NTT domain)
 * 
 * Computes r[i] = a[i] * b[i] mod q for all i.
 */
void ntt_pointwise_mul(poly_coeff_t r[DLPL_N],
                       const poly_coeff_t a[DLPL_N],
                       const poly_coeff_t b[DLPL_N]);

/**
 * @brief Point-wise multiply-accumulate in NTT domain
 * @param r Result accumulator (NTT domain)
 * @param a First operand (NTT domain)
 * @param b Second operand (NTT domain)
 * 
 * Computes r[i] += a[i] * b[i] mod q for all i.
 */
void ntt_pointwise_mac(poly_coeff_t r[DLPL_N],
                       const poly_coeff_t a[DLPL_N],
                       const poly_coeff_t b[DLPL_N]);

/* ==========================================================================
 * High-Level Polynomial Operations
 * ========================================================================== */

/**
 * @brief Multiply two polynomials using NTT
 * @param r Result polynomial
 * @param a First polynomial (coefficient domain)
 * @param b Second polynomial (coefficient domain)
 * 
 * Computes r = a * b mod (x^n + 1) in O(n log n) time.
 */
void poly_mul_ntt(poly_t *r, const poly_t *a, const poly_t *b);

/**
 * @brief Convert polynomial to NTT domain
 * @param p Polynomial (modified in place)
 */
void poly_to_ntt(poly_t *p);

/**
 * @brief Convert polynomial from NTT domain
 * @param p Polynomial in NTT form (modified in place)
 */
void poly_from_ntt(poly_t *p);

/* ==========================================================================
 * Modular Arithmetic (Constant-Time)
 * ========================================================================== */

/**
 * @brief Barrett reduction: x mod q
 * @param x Value to reduce (must be < q^2)
 * @return x mod q
 * 
 * Constant-time modular reduction without division.
 */
static inline poly_coeff_t barrett_reduce(poly_wide_t x);

/**
 * @brief Montgomery reduction
 * @param x Value to reduce (in Montgomery form)
 * @return x * R^(-1) mod q
 */
static inline poly_coeff_t montgomery_reduce(poly_wide_t x);

/**
 * @brief Conditional subtraction: if x >= q then x - q
 * @param x Value to conditionally reduce
 * @return x mod q (assuming x < 2q)
 * 
 * Constant-time (no branches on secret data).
 */
static inline poly_coeff_t cond_sub_q(poly_coeff_t x);

/* ==========================================================================
 * Implementation of Inline Functions
 * ========================================================================== */

/* Barrett reduction constants (precomputed) */
#define BARRETT_SHIFT   (2 * DLPL_LOGQ)
#define BARRETT_MU      ((1ULL << BARRETT_SHIFT) / DLPL_Q + 1)

static inline poly_coeff_t barrett_reduce(poly_wide_t x) {
    poly_wide_t t;
    t = ((poly_acc_t)x * BARRETT_MU) >> BARRETT_SHIFT;
    t = x - t * DLPL_Q;
    /* Constant-time conditional subtraction */
    t -= DLPL_Q & -((DLPL_Q - 1 - t) >> 31);
    t -= DLPL_Q & -((DLPL_Q - 1 - t) >> 31);
    return (poly_coeff_t)t;
}

/* Montgomery constants - defined in dlpl_ntt.c */
#ifndef MONT_R
#define MONT_R          (1 << 16)
#define MONT_R_MASK     (MONT_R - 1)
#endif
/* Q_PRIME such that Q * Q_PRIME ≡ -1 (mod R) - computed at init */
extern int32_t MONT_Q_PRIME;

static inline poly_coeff_t montgomery_reduce(poly_wide_t x) {
    poly_wide_t t;
    t = (poly_coeff_t)x * MONT_Q_PRIME;
    t = (x - (poly_wide_t)(poly_coeff_t)t * DLPL_Q) >> 16;
    /* Constant-time conditional subtraction */
    t += DLPL_Q & -(t >> 31);
    t -= DLPL_Q & -((DLPL_Q - 1 - t) >> 31);
    return (poly_coeff_t)t;
}

static inline poly_coeff_t cond_sub_q(poly_coeff_t x) {
    /* If x >= q, subtract q. Constant-time. */
    int32_t x32 = x;
    int32_t mask = -(x32 >= DLPL_Q);  /* -1 (all 1s) if x >= q, 0 otherwise */
    x32 -= DLPL_Q & mask;
    return (poly_coeff_t)x32;
}

/**
 * @brief Reduce coefficient to centered range [-q/2, q/2]
 * @param x Coefficient in [0, q-1]
 * @return Coefficient in [-(q-1)/2, q/2]
 */
static inline poly_coeff_t to_centered(poly_coeff_t x) {
    return x - (DLPL_Q & -(x > DLPL_Q/2));
}

/**
 * @brief Reduce coefficient to positive range [0, q-1]
 * @param x Coefficient (possibly negative)
 * @return Coefficient in [0, q-1]
 */
static inline poly_coeff_t to_positive(poly_coeff_t x) {
    return x + (DLPL_Q & -(x >> 15));
}

#endif /* DLPL_NTT_H */
