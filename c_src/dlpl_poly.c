/**
 * @file dlpl_poly.c
 * @brief Polynomial and matrix operations implementation
 */

#include "dlpl_poly.h"
#include <string.h>

/* ==========================================================================
 * Polynomial Operations
 * ========================================================================== */

void poly_zero(poly_t *p) {
    memset(p->coeffs, 0, sizeof(p->coeffs));
}

void poly_one(poly_t *p) {
    poly_zero(p);
    p->coeffs[0] = 1;
}

void poly_copy(poly_t *dest, const poly_t *src) {
    memcpy(dest, src, sizeof(poly_t));
}

void poly_add(poly_t *r, const poly_t *a, const poly_t *b) {
    for (int i = 0; i < DLPL_N; i++) {
        r->coeffs[i] = cond_sub_q(a->coeffs[i] + b->coeffs[i]);
    }
}

void poly_sub(poly_t *r, const poly_t *a, const poly_t *b) {
    for (int i = 0; i < DLPL_N; i++) {
        poly_coeff_t t = a->coeffs[i] - b->coeffs[i];
        r->coeffs[i] = t + (DLPL_Q & (t >> 15));  /* Add q if negative */
    }
}

void poly_neg(poly_t *r, const poly_t *a) {
    for (int i = 0; i < DLPL_N; i++) {
        r->coeffs[i] = (DLPL_Q - a->coeffs[i]) % DLPL_Q;
    }
}

void poly_scalar_mul(poly_t *r, const poly_t *a, poly_coeff_t s) {
    for (int i = 0; i < DLPL_N; i++) {
        r->coeffs[i] = barrett_reduce((poly_wide_t)a->coeffs[i] * s);
    }
}

void poly_reduce(poly_t *p) {
    for (int i = 0; i < DLPL_N; i++) {
        p->coeffs[i] = barrett_reduce(p->coeffs[i]);
    }
}

int16_t poly_norm_inf(const poly_t *p) {
    int16_t max = 0;
    for (int i = 0; i < DLPL_N; i++) {
        int16_t c = to_centered(p->coeffs[i]);
        int16_t abs_c = c < 0 ? -c : c;
        if (abs_c > max) max = abs_c;
    }
    return max;
}

int poly_equal(const poly_t *a, const poly_t *b) {
    poly_coeff_t diff = 0;
    for (int i = 0; i < DLPL_N; i++) {
        diff |= a->coeffs[i] ^ b->coeffs[i];
    }
    return diff == 0;
}

/* Extended GCD for scalar modular inverse */
static int32_t scalar_mod_inv(int32_t a, int32_t m) {
    int32_t m0 = m, y = 0, x = 1;
    if (m == 1) return 0;
    a = ((a % m) + m) % m;
    while (a > 1) {
        int32_t q = a / m;
        int32_t t = m;
        m = a % m;
        a = t;
        t = y;
        y = x - q * y;
        x = t;
    }
    return (x % m0 + m0) % m0;
}

/**
 * @brief Polynomial inverse in R_q = Z_q[x]/(x^n + 1) using NTT
 * 
 * A polynomial f is invertible iff f(psi^(2i+1)) != 0 for i = 0..n-1,
 * where psi is a primitive 2n-th root of unity.
 * 
 * The inverse is computed by:
 * 1. Transform f to NTT domain: f_ntt = NTT(f)
 * 2. Compute pointwise inverses: g_ntt[i] = f_ntt[i]^(-1) mod q
 * 3. Transform back: g = INTT(g_ntt)
 */
int poly_inverse(poly_t *r, const poly_t *a) {
    poly_t a_ntt;
    
    /* Transform to NTT domain */
    poly_copy(&a_ntt, a);
    ntt_forward(a_ntt.coeffs);
    
    /* Check invertibility and compute pointwise inverses */
    for (int i = 0; i < DLPL_N; i++) {
        if (a_ntt.coeffs[i] == 0) {
            /* Not invertible - has a root at this evaluation point */
            return 0;
        }
        /* Compute modular inverse of each coefficient */
        a_ntt.coeffs[i] = (poly_coeff_t)scalar_mod_inv(a_ntt.coeffs[i], DLPL_Q);
    }
    
    /* Transform back */
    poly_copy(r, &a_ntt);
    ntt_inverse(r->coeffs);
    
    return 1;
}

/* ==========================================================================
 * Block-Circulant Matrix Operations
 * ========================================================================== */

void bc_zero(bc_matrix_t *m) {
    for (int i = 0; i < DLPL_K; i++) {
        poly_zero(&m->row[i]);
    }
}

void bc_identity(bc_matrix_t *m) {
    bc_zero(m);
    m->row[0].coeffs[0] = 1;  /* Only (0,0) element is 1 */
}

void bc_copy(bc_matrix_t *dest, const bc_matrix_t *src) {
    memcpy(dest, src, sizeof(bc_matrix_t));
}

void bc_get_block(poly_t *p, const bc_matrix_t *m, int i, int j) {
    /* Block-circulant: M[i][j] = row[(j - i + k) % k] */
    int idx = (j - i + DLPL_K) % DLPL_K;
    poly_copy(p, &m->row[idx]);
}

void bc_add(bc_matrix_t *r, const bc_matrix_t *a, const bc_matrix_t *b) {
    for (int i = 0; i < DLPL_K; i++) {
        poly_add(&r->row[i], &a->row[i], &b->row[i]);
    }
}

void bc_sub(bc_matrix_t *r, const bc_matrix_t *a, const bc_matrix_t *b) {
    for (int i = 0; i < DLPL_K; i++) {
        poly_sub(&r->row[i], &a->row[i], &b->row[i]);
    }
}

void bc_neg(bc_matrix_t *r, const bc_matrix_t *a) {
    for (int i = 0; i < DLPL_K; i++) {
        poly_neg(&r->row[i], &a->row[i]);
    }
}

void bc_mul(bc_matrix_t *r, const bc_matrix_t *a, const bc_matrix_t *b) {
    bc_matrix_t result;
    bc_zero(&result);
    
    /* 
     * Block-circulant multiplication uses cyclic convolution
     * result.row[j] = sum_{l=0}^{k-1} a.row[l] * b.row[(j-l+k)%k]
     */
    for (int j = 0; j < DLPL_K; j++) {
        poly_t acc;
        poly_zero(&acc);
        
        for (int l = 0; l < DLPL_K; l++) {
            poly_t b_block;
            bc_get_block(&b_block, b, l, j);
            
            poly_t prod;
            poly_mul_ntt(&prod, &a->row[l], &b_block);
            poly_add(&acc, &acc, &prod);
        }
        poly_copy(&result.row[j], &acc);
    }
    
    bc_copy(r, &result);
}

int bc_inverse(bc_matrix_t *r, const bc_matrix_t *a) {
#if DLPL_K == 2
    /* 
     * For k=2: M = [[a, b], [b, a]] (block-circulant, row = [a, b])
     * det(M) = a² - b² = (a+b)(a-b)
     * adj(M) = [[a, -b], [-b, a]]
     * M^(-1) = adj(M) * det^(-1) = [[a*det^(-1), -b*det^(-1)], 
     *                               [-b*det^(-1), a*det^(-1)]]
     * So M^(-1).row[0] = a * det^(-1), M^(-1).row[1] = -b * det^(-1)
     */
    poly_t a0, a1, sum, diff, det, det_inv;
    poly_t inv_r0, inv_r1;
    
    poly_copy(&a0, &a->row[0]);
    poly_copy(&a1, &a->row[1]);
    
    /* sum = a0 + a1, diff = a0 - a1 */
    poly_add(&sum, &a0, &a1);
    poly_sub(&diff, &a0, &a1);
    
    /* det = sum * diff = (a0 + a1)(a0 - a1) = a0² - a1² */
    poly_mul_ntt(&det, &sum, &diff);
    
    /* Compute det^-1 */
    if (!poly_inverse(&det_inv, &det)) {
        return 0;
    }
    
    /* inv_r0 = a0 * det_inv */
    poly_mul_ntt(&inv_r0, &a0, &det_inv);
    
    /* inv_r1 = -a1 * det_inv */
    poly_t neg_a1;
    poly_neg(&neg_a1, &a1);
    poly_mul_ntt(&inv_r1, &neg_a1, &det_inv);
    
    poly_copy(&r->row[0], &inv_r0);
    poly_copy(&r->row[1], &inv_r1);
    
    return 1;
    
#elif DLPL_K == 3
    /* For k=3: det = a³ + b³ + c³ - 3abc */
    poly_t a0, a1, a2;
    poly_copy(&a0, &a->row[0]);
    poly_copy(&a1, &a->row[1]);
    poly_copy(&a2, &a->row[2]);
    
    /* Compute det = a0³ + a1³ + a2³ - 3*a0*a1*a2 */
    poly_t a0_sq, a1_sq, a2_sq;
    poly_t a0_cb, a1_cb, a2_cb;
    poly_t abc, abc3, det, det_inv;
    
    poly_mul_ntt(&a0_sq, &a0, &a0);
    poly_mul_ntt(&a1_sq, &a1, &a1);
    poly_mul_ntt(&a2_sq, &a2, &a2);
    
    poly_mul_ntt(&a0_cb, &a0_sq, &a0);
    poly_mul_ntt(&a1_cb, &a1_sq, &a1);
    poly_mul_ntt(&a2_cb, &a2_sq, &a2);
    
    poly_mul_ntt(&abc, &a0, &a1);
    poly_mul_ntt(&abc, &abc, &a2);
    poly_add(&abc3, &abc, &abc);
    poly_add(&abc3, &abc3, &abc);  /* abc3 = 3*abc */
    
    poly_add(&det, &a0_cb, &a1_cb);
    poly_add(&det, &det, &a2_cb);
    poly_sub(&det, &det, &abc3);
    
    if (!poly_inverse(&det_inv, &det)) {
        return 0;
    }
    
    /* Compute adjugate matrix elements */
    /* adj[0] = a0² - a1*a2 */
    /* adj[1] = a2² - a0*a1 */
    /* adj[2] = a1² - a0*a2 */
    poly_t a01, a02, a12;
    poly_mul_ntt(&a01, &a0, &a1);
    poly_mul_ntt(&a02, &a0, &a2);
    poly_mul_ntt(&a12, &a1, &a2);
    
    poly_t adj0, adj1, adj2;
    poly_sub(&adj0, &a0_sq, &a12);
    poly_sub(&adj1, &a2_sq, &a01);
    poly_sub(&adj2, &a1_sq, &a02);
    
    /* Multiply by det_inv */
    poly_mul_ntt(&r->row[0], &adj0, &det_inv);
    poly_mul_ntt(&r->row[1], &adj1, &det_inv);
    poly_mul_ntt(&r->row[2], &adj2, &det_inv);
    
    return 1;
    
#elif DLPL_K == 4
    /*
     * For k=4: Block-circulant M = circ(a0, a1, a2, a3)
     * Use DFT decomposition: eigenvalues are
     * λ_j = a0 + ω^j*a1 + ω^(2j)*a2 + ω^(3j)*a3, j=0,1,2,3
     * where ω = i (primitive 4th root of unity, ω^2 = -1)
     * 
     * λ_0 = a0 + a1 + a2 + a3
     * λ_1 = a0 + i*a1 - a2 - i*a3 = (a0-a2) + i*(a1-a3)
     * λ_2 = a0 - a1 + a2 - a3
     * λ_3 = a0 - i*a1 - a2 + i*a3 = (a0-a2) - i*(a1-a3) = conj(λ_1)
     * 
     * det(M) = λ_0 * λ_1 * λ_2 * λ_3 = λ_0 * λ_2 * |λ_1|²
     * |λ_1|² = (a0-a2)² + (a1-a3)²
     */
    poly_t a0, a1, a2, a3;
    poly_copy(&a0, &a->row[0]);
    poly_copy(&a1, &a->row[1]);
    poly_copy(&a2, &a->row[2]);
    poly_copy(&a3, &a->row[3]);
    
    /* Compute eigenvalues (real parts for λ_0, λ_2) */
    poly_t lam0, lam2;  /* λ_0 = a0+a1+a2+a3, λ_2 = a0-a1+a2-a3 */
    poly_t sum01, sum23, diff01, diff23;
    poly_add(&sum01, &a0, &a1);
    poly_add(&sum23, &a2, &a3);
    poly_sub(&diff01, &a0, &a1);
    poly_sub(&diff23, &a2, &a3);
    poly_add(&lam0, &sum01, &sum23);      /* λ_0 = (a0+a1) + (a2+a3) */
    poly_add(&lam2, &diff01, &diff23);    /* λ_2 = (a0-a1) + (a2-a3) */
    
    /* For λ_1 = (a0-a2) + i*(a1-a3): |λ_1|² = (a0-a2)² + (a1-a3)² */
    poly_t diff02, diff13;
    poly_sub(&diff02, &a0, &a2);
    poly_sub(&diff13, &a1, &a3);
    poly_t diff02_sq, diff13_sq, lam1_norm;
    poly_mul_ntt(&diff02_sq, &diff02, &diff02);
    poly_mul_ntt(&diff13_sq, &diff13, &diff13);
    poly_add(&lam1_norm, &diff02_sq, &diff13_sq);  /* |λ_1|² */
    
    /* det = λ_0 * λ_2 * |λ_1|² */
    poly_t lam02, det, det_inv;
    poly_mul_ntt(&lam02, &lam0, &lam2);
    poly_mul_ntt(&det, &lam02, &lam1_norm);
    
    if (!poly_inverse(&det_inv, &det)) {
        return 0;
    }
    
    /* Compute individual eigenvalue inverses */
    poly_t lam0_inv, lam2_inv, lam1_norm_inv;
    if (!poly_inverse(&lam0_inv, &lam0)) return 0;
    if (!poly_inverse(&lam2_inv, &lam2)) return 0;
    if (!poly_inverse(&lam1_norm_inv, &lam1_norm)) return 0;
    
    /* λ_1^(-1) = conj(λ_1) / |λ_1|² = ((a0-a2) - i*(a1-a3)) / |λ_1|²
     * Re(λ_1^(-1)) = (a0-a2) / |λ_1|²
     * Im(λ_1^(-1)) = -(a1-a3) / |λ_1|²
     */
    poly_t lam1_inv_re, lam1_inv_im, neg_diff13;
    poly_mul_ntt(&lam1_inv_re, &diff02, &lam1_norm_inv);
    poly_neg(&neg_diff13, &diff13);
    poly_mul_ntt(&lam1_inv_im, &neg_diff13, &lam1_norm_inv);
    
    /* Inverse DFT to get M^(-1) row:
     * M^(-1)[0,j] = (1/4) * Σ_k ω^(-jk) * λ_k^(-1)
     * 
     * r0 = (1/4)(λ_0^-1 + λ_1^-1 + λ_2^-1 + λ_3^-1)
     *    = (1/4)(λ_0^-1 + λ_2^-1 + 2*Re(λ_1^-1))
     * r1 = (1/4)(λ_0^-1 - i*λ_1^-1 - λ_2^-1 + i*λ_3^-1)
     *    = (1/4)(λ_0^-1 - λ_2^-1 + 2*Im(λ_1^-1))
     * r2 = (1/4)(λ_0^-1 - λ_1^-1 + λ_2^-1 - λ_3^-1)
     *    = (1/4)(λ_0^-1 + λ_2^-1 - 2*Re(λ_1^-1))
     * r3 = (1/4)(λ_0^-1 + i*λ_1^-1 - λ_2^-1 - i*λ_3^-1)
     *    = (1/4)(λ_0^-1 - λ_2^-1 - 2*Im(λ_1^-1))
     */
    poly_t sum_lam_inv, diff_lam_inv, two_re, two_im;
    poly_add(&sum_lam_inv, &lam0_inv, &lam2_inv);
    poly_sub(&diff_lam_inv, &lam0_inv, &lam2_inv);
    poly_add(&two_re, &lam1_inv_re, &lam1_inv_re);
    poly_add(&two_im, &lam1_inv_im, &lam1_inv_im);
    
    poly_t r0_4, r1_4, r2_4, r3_4;
    poly_add(&r0_4, &sum_lam_inv, &two_re);    /* 4*r0 */
    poly_add(&r1_4, &diff_lam_inv, &two_im);   /* 4*r1 */
    poly_sub(&r2_4, &sum_lam_inv, &two_re);    /* 4*r2 */
    poly_sub(&r3_4, &diff_lam_inv, &two_im);   /* 4*r3 */
    
    /* Multiply by 4^-1 mod q */
    int64_t four_inv;
    {
        /* 4^-1 mod q using Fermat: 4^(q-2) mod q */
        int64_t q = DLPL_Q;
        /* For odd q: 4^-1 = (q+1)/4 if q ≡ 3 (mod 4), else compute */
        int64_t base = 4, exp = q - 2, result = 1;
        while (exp > 0) {
            if (exp & 1) result = (result * base) % q;
            base = (base * base) % q;
            exp >>= 1;
        }
        four_inv = result;
    }
    
    for (int i = 0; i < DLPL_N; i++) {
        int64_t c0 = ((int64_t)r0_4.coeffs[i] * four_inv) % DLPL_Q;
        int64_t c1 = ((int64_t)r1_4.coeffs[i] * four_inv) % DLPL_Q;
        int64_t c2 = ((int64_t)r2_4.coeffs[i] * four_inv) % DLPL_Q;
        int64_t c3 = ((int64_t)r3_4.coeffs[i] * four_inv) % DLPL_Q;
        r->row[0].coeffs[i] = (poly_coeff_t)(c0 < 0 ? c0 + DLPL_Q : c0);
        r->row[1].coeffs[i] = (poly_coeff_t)(c1 < 0 ? c1 + DLPL_Q : c1);
        r->row[2].coeffs[i] = (poly_coeff_t)(c2 < 0 ? c2 + DLPL_Q : c2);
        r->row[3].coeffs[i] = (poly_coeff_t)(c3 < 0 ? c3 + DLPL_Q : c3);
    }
    
    return 1;
    
#else
    /* General case: not implemented in optimized version */
    /* Would use DFT decomposition over k-th roots of unity */
    (void)r;
    (void)a;
    return 0;
#endif
}

int bc_inverse_blinded(bc_matrix_t *r, const bc_matrix_t *a) {
    /* Blinded inversion: compute (a * rand)^-1 * rand */
    /* TODO: Implement proper blinding */
    return bc_inverse(r, a);
}

/* ==========================================================================
 * General Matrix Operations
 * ========================================================================== */

void gm_zero(general_matrix_t *m) {
    for (int i = 0; i < DLPL_K; i++) {
        for (int j = 0; j < DLPL_K; j++) {
            poly_zero(&m->blocks[i][j]);
        }
    }
}

void gm_identity(general_matrix_t *m) {
    gm_zero(m);
    for (int i = 0; i < DLPL_K; i++) {
        m->blocks[i][i].coeffs[0] = 1;
    }
}

void gm_copy(general_matrix_t *dest, const general_matrix_t *src) {
    memcpy(dest, src, sizeof(general_matrix_t));
}

void gm_add(general_matrix_t *r, const general_matrix_t *a, const general_matrix_t *b) {
    for (int i = 0; i < DLPL_K; i++) {
        for (int j = 0; j < DLPL_K; j++) {
            poly_add(&r->blocks[i][j], &a->blocks[i][j], &b->blocks[i][j]);
        }
    }
}

void gm_sub(general_matrix_t *r, const general_matrix_t *a, const general_matrix_t *b) {
    for (int i = 0; i < DLPL_K; i++) {
        for (int j = 0; j < DLPL_K; j++) {
            poly_sub(&r->blocks[i][j], &a->blocks[i][j], &b->blocks[i][j]);
        }
    }
}

void gm_add_bc(general_matrix_t *r, const general_matrix_t *a, const bc_matrix_t *b) {
    for (int i = 0; i < DLPL_K; i++) {
        for (int j = 0; j < DLPL_K; j++) {
            poly_t b_block;
            bc_get_block(&b_block, b, i, j);
            poly_add(&r->blocks[i][j], &a->blocks[i][j], &b_block);
        }
    }
}

void gm_sub_bc(general_matrix_t *r, const general_matrix_t *a, const bc_matrix_t *b) {
    for (int i = 0; i < DLPL_K; i++) {
        for (int j = 0; j < DLPL_K; j++) {
            poly_t b_block;
            bc_get_block(&b_block, b, i, j);
            poly_sub(&r->blocks[i][j], &a->blocks[i][j], &b_block);
        }
    }
}

void gm_mul(general_matrix_t *r, const general_matrix_t *a, const general_matrix_t *b) {
    general_matrix_t result;
    
    for (int i = 0; i < DLPL_K; i++) {
        for (int j = 0; j < DLPL_K; j++) {
            poly_t acc;
            poly_zero(&acc);
            
            for (int l = 0; l < DLPL_K; l++) {
                poly_t prod;
                poly_mul_ntt(&prod, &a->blocks[i][l], &b->blocks[l][j]);
                poly_add(&acc, &acc, &prod);
            }
            poly_copy(&result.blocks[i][j], &acc);
        }
    }
    
    gm_copy(r, &result);
}

void bc_mul_gm(general_matrix_t *r, const bc_matrix_t *bc, const general_matrix_t *gm) {
    general_matrix_t result;
    
    for (int i = 0; i < DLPL_K; i++) {
        for (int j = 0; j < DLPL_K; j++) {
            poly_t acc;
            poly_zero(&acc);
            
            for (int l = 0; l < DLPL_K; l++) {
                poly_t bc_block, prod;
                bc_get_block(&bc_block, bc, i, l);
                poly_mul_ntt(&prod, &bc_block, &gm->blocks[l][j]);
                poly_add(&acc, &acc, &prod);
            }
            poly_copy(&result.blocks[i][j], &acc);
        }
    }
    
    gm_copy(r, &result);
}

void gm_mul_bc(general_matrix_t *r, const general_matrix_t *gm, const bc_matrix_t *bc) {
    general_matrix_t result;
    
    for (int i = 0; i < DLPL_K; i++) {
        for (int j = 0; j < DLPL_K; j++) {
            poly_t acc;
            poly_zero(&acc);
            
            for (int l = 0; l < DLPL_K; l++) {
                poly_t bc_block, prod;
                bc_get_block(&bc_block, bc, l, j);
                poly_mul_ntt(&prod, &gm->blocks[i][l], &bc_block);
                poly_add(&acc, &acc, &prod);
            }
            poly_copy(&result.blocks[i][j], &acc);
        }
    }
    
    gm_copy(r, &result);
}

/* ==========================================================================
 * Serialization (Kyber-style bit-packing)
 * ========================================================================== */

/**
 * @brief Encode polynomial to bytes using bit-packing (Kyber-style)
 * Each coefficient is packed using DLPL_LOGQ bits
 * @param out Output buffer (size DLPL_POLY_BYTES)
 * @param p Input polynomial
 */
void poly_to_bytes(uint8_t *out, const poly_t *p) {
    /* Zero-initialize output buffer */
    for (int i = 0; i < DLPL_POLY_BYTES; i++) {
        out[i] = 0;
    }
    
    /* Bit-pack coefficients using DLPL_LOGQ bits each */
    int bit_pos = 0;
    for (int i = 0; i < DLPL_N; i++) {
        uint16_t coeff = (uint16_t)(p->coeffs[i] & ((1 << DLPL_LOGQ) - 1));
        
        /* Pack each bit of the coefficient */
        for (int b = 0; b < DLPL_LOGQ; b++) {
            if (coeff & (1 << b)) {
                out[bit_pos / 8] |= (1 << (bit_pos % 8));
            }
            bit_pos++;
        }
    }
}

/**
 * @brief Decode polynomial from bytes using bit-unpacking (Kyber-style)
 * @param p Output polynomial
 * @param in Input buffer (size DLPL_POLY_BYTES)
 */
void poly_from_bytes(poly_t *p, const uint8_t *in) {
    int bit_pos = 0;
    for (int i = 0; i < DLPL_N; i++) {
        uint16_t coeff = 0;
        
        /* Unpack each bit of the coefficient */
        for (int b = 0; b < DLPL_LOGQ; b++) {
            if (in[bit_pos / 8] & (1 << (bit_pos % 8))) {
                coeff |= (1 << b);
            }
            bit_pos++;
        }
        
        p->coeffs[i] = (poly_coeff_t)coeff;
        p->coeffs[i] = cond_sub_q(p->coeffs[i]);
    }
}

void bc_to_bytes(uint8_t *out, const bc_matrix_t *m) {
    for (int i = 0; i < DLPL_K; i++) {
        poly_to_bytes(out + i * DLPL_POLY_BYTES, &m->row[i]);
    }
}

void bc_from_bytes(bc_matrix_t *m, const uint8_t *in) {
    for (int i = 0; i < DLPL_K; i++) {
        poly_from_bytes(&m->row[i], in + i * DLPL_POLY_BYTES);
    }
}

void gm_to_bytes(uint8_t *out, const general_matrix_t *m) {
    int offset = 0;
    for (int i = 0; i < DLPL_K; i++) {
        for (int j = 0; j < DLPL_K; j++) {
            poly_to_bytes(out + offset, &m->blocks[i][j]);
            offset += DLPL_POLY_BYTES;
        }
    }
}

void gm_from_bytes(general_matrix_t *m, const uint8_t *in) {
    int offset = 0;
    for (int i = 0; i < DLPL_K; i++) {
        for (int j = 0; j < DLPL_K; j++) {
            poly_from_bytes(&m->blocks[i][j], in + offset);
            offset += DLPL_POLY_BYTES;
        }
    }
}
