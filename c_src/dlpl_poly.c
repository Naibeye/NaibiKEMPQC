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
     * Use factorization: det = det(A+C) * det(A-C) where
     * A = a0 + a2, C = a1 + a3, B = a0 - a2, D = a1 - a3
     * det = ((A+B)(A-B) - (C+D)(C-D)) for Cayley-like approach
     * 
     * Simpler approach using eigenvalue decomposition:
     * In Fourier domain with 4th root of unity omega (omega^4=1, omega^2=-1):
     * lambda_j = a0 + omega^j*a1 + omega^(2j)*a2 + omega^(3j)*a3
     * det(M) = prod_j lambda_j
     * 
     * For R[x]/(x^n+1) with NTT-friendly q, we compute pointwise.
     */
    poly_t a0, a1, a2, a3;
    poly_copy(&a0, &a->row[0]);
    poly_copy(&a1, &a->row[1]);
    poly_copy(&a2, &a->row[2]);
    poly_copy(&a3, &a->row[3]);
    
    /* Compute sums for 2x2 block decomposition:
     * M = [[A, B], [B, A]] where A=circ(a0,a2), B=circ(a1,a3)
     * det(M) = det(A+B)*det(A-B)
     * A+B row = [a0+a1, a2+a3], A-B row = [a0-a1, a2-a3]
     */
    poly_t sum02, sum13, diff02, diff13;
    poly_add(&sum02, &a0, &a2);
    poly_add(&sum13, &a1, &a3);
    poly_sub(&diff02, &a0, &a2);
    poly_sub(&diff13, &a1, &a3);
    
    /* det1 = det(A+B) = (sum02+sum13)*(sum02-sum13) for k=2 circulant */
    /* det2 = det(A-B) = (diff02+diff13)*(diff02-diff13) */
    poly_t apb_sum, apb_diff, det1;
    poly_add(&apb_sum, &sum02, &sum13);
    poly_sub(&apb_diff, &sum02, &sum13);
    poly_mul_ntt(&det1, &apb_sum, &apb_diff);
    
    poly_t amb_sum, amb_diff, det2;
    poly_add(&amb_sum, &diff02, &diff13);
    poly_sub(&amb_diff, &diff02, &diff13);
    poly_mul_ntt(&det2, &amb_sum, &amb_diff);
    
    /* Total det = det1 * det2 */
    poly_t det, det_inv;
    poly_mul_ntt(&det, &det1, &det2);
    
    if (!poly_inverse(&det_inv, &det)) {
        return 0;
    }
    
    /* Compute partial inverses for det1 and det2 */
    poly_t det1_inv, det2_inv;
    if (!poly_inverse(&det1_inv, &det1) || !poly_inverse(&det2_inv, &det2)) {
        return 0;
    }
    
    /* Inverse of k=2 circulant: inv(circ(x,y)) = circ(x/(x²-y²), -y/(x²-y²))
     * (A+B)^-1 = circ(sum02*det1_inv, -sum13*det1_inv)
     * (A-B)^-1 = circ(diff02*det2_inv, -diff13*det2_inv)
     */
    poly_t inv_apb0, inv_apb1, inv_amb0, inv_amb1;
    poly_t neg_sum13, neg_diff13;
    
    poly_mul_ntt(&inv_apb0, &sum02, &det1_inv);
    poly_neg(&neg_sum13, &sum13);
    poly_mul_ntt(&inv_apb1, &neg_sum13, &det1_inv);
    
    poly_mul_ntt(&inv_amb0, &diff02, &det2_inv);
    poly_neg(&neg_diff13, &diff13);
    poly_mul_ntt(&inv_amb1, &neg_diff13, &det2_inv);
    
    /* Reconstruct M^-1: 
     * M^-1 = 0.5 * [[(A+B)^-1 + (A-B)^-1, (A+B)^-1 - (A-B)^-1],
     *               [(A+B)^-1 - (A-B)^-1, (A+B)^-1 + (A-B)^-1]]
     * But we want first row of block-circulant result.
     * r[0] = 0.5*(inv_apb0 + inv_amb0)
     * r[1] = 0.5*(inv_apb1 + inv_amb1) 
     * r[2] = 0.5*(inv_apb0 - inv_amb0)
     * r[3] = 0.5*(inv_apb1 - inv_amb1)
     */
    poly_t half_sum0, half_sum1, half_diff0, half_diff1;
    poly_add(&half_sum0, &inv_apb0, &inv_amb0);
    poly_add(&half_sum1, &inv_apb1, &inv_amb1);
    poly_sub(&half_diff0, &inv_apb0, &inv_amb0);
    poly_sub(&half_diff1, &inv_apb1, &inv_amb1);
    
    /* Multiply by 2^-1 mod q */
    int64_t two_inv = 1;
    {
        /* Extended Euclidean: 2 * x ≡ 1 (mod q) */
        int64_t q = DLPL_Q;
        two_inv = (q + 1) / 2;  /* Works since q is odd */
    }
    
    for (int i = 0; i < DLPL_N; i++) {
        r->row[0].coeffs[i] = (poly_coeff_t)(((int64_t)half_sum0.coeffs[i] * two_inv) % DLPL_Q);
        r->row[1].coeffs[i] = (poly_coeff_t)(((int64_t)half_sum1.coeffs[i] * two_inv) % DLPL_Q);
        r->row[2].coeffs[i] = (poly_coeff_t)(((int64_t)half_diff0.coeffs[i] * two_inv) % DLPL_Q);
        r->row[3].coeffs[i] = (poly_coeff_t)(((int64_t)half_diff1.coeffs[i] * two_inv) % DLPL_Q);
        /* Normalize to [0, q) */
        if (r->row[0].coeffs[i] < 0) r->row[0].coeffs[i] += DLPL_Q;
        if (r->row[1].coeffs[i] < 0) r->row[1].coeffs[i] += DLPL_Q;
        if (r->row[2].coeffs[i] < 0) r->row[2].coeffs[i] += DLPL_Q;
        if (r->row[3].coeffs[i] < 0) r->row[3].coeffs[i] += DLPL_Q;
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
 * Serialization
 * ========================================================================== */

void poly_to_bytes(uint8_t *out, const poly_t *p) {
    /* Pack coefficients (assuming DLPL_LOGQ <= 16) */
    for (int i = 0; i < DLPL_N; i++) {
        out[2*i] = p->coeffs[i] & 0xFF;
        out[2*i + 1] = (p->coeffs[i] >> 8) & 0xFF;
    }
}

void poly_from_bytes(poly_t *p, const uint8_t *in) {
    for (int i = 0; i < DLPL_N; i++) {
        p->coeffs[i] = (poly_coeff_t)in[2*i] | ((poly_coeff_t)in[2*i + 1] << 8);
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
