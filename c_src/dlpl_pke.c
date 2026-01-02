/**
 * @file dlpl_pke.c
 * @brief DLPL-DH PKE scheme implementation
 */

#include "dlpl_pke.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Simple SHAKE-256 / SHA-256 implementation or use external library */
/* For production, use OpenSSL or similar */

/* ==========================================================================
 * Minimal PRNG (for demonstration - use proper CSPRNG in production)
 * ========================================================================== */

static uint64_t prng_state[4];

static uint64_t rotl(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

/* xoshiro256** PRNG */
static uint64_t prng_next(void) {
    uint64_t result = rotl(prng_state[1] * 5, 7) * 9;
    uint64_t t = prng_state[1] << 17;
    
    prng_state[2] ^= prng_state[0];
    prng_state[3] ^= prng_state[1];
    prng_state[1] ^= prng_state[2];
    prng_state[0] ^= prng_state[3];
    prng_state[2] ^= t;
    prng_state[3] = rotl(prng_state[3], 45);
    
    return result;
}

static void prng_seed(const uint8_t seed[32]) {
    if (seed == NULL) {
        /* Use fixed seed if NULL */
        prng_state[0] = 0x853c49e6748fea9bULL;
        prng_state[1] = 0xda3e39cb94b95bdbULL;
        prng_state[2] = 0x9c2c1d3e4f5a6b7cULL;
        prng_state[3] = 0x1234567890abcdefULL;
        return;
    }
    memcpy(prng_state, seed, 32);
    if (prng_state[0] == 0 && prng_state[1] == 0 && 
        prng_state[2] == 0 && prng_state[3] == 0) {
        prng_state[0] = 0x853c49e6748fea9bULL;
        prng_state[1] = 0xda3e39cb94b95bdbULL;
        prng_state[2] = 0x9c2c1d3e4f5a6b7cULL;
        prng_state[3] = 0x1234567890abcdefULL;
    }
}

static uint32_t prng_random32(void) {
    return (uint32_t)(prng_next() >> 32);
}

void dlpl_random_init(const uint8_t seed[32]) {
    if (seed) {
        prng_seed(seed);
    } else {
        /* Use system random if available */
        uint8_t default_seed[32] = {0};
        #ifdef __linux__
        FILE *f = fopen("/dev/urandom", "rb");
        if (f) {
            fread(default_seed, 1, 32, f);
            fclose(f);
        }
        #endif
        prng_seed(default_seed);
    }
    
    /* Initialize NTT tables */
    ntt_init();
}

/* ==========================================================================
 * Sampling Functions
 * ========================================================================== */

void poly_sample_uniform(poly_t *p) {
    for (int i = 0; i < DLPL_N; i++) {
        /* Rejection sampling for uniform mod q */
        uint32_t r;
        do {
            r = prng_random32() & ((1 << DLPL_LOGQ) - 1);
        } while (r >= DLPL_Q);
        p->coeffs[i] = (poly_coeff_t)r;
    }
}

void poly_sample_cbd(poly_t *p, int eta) {
    /* Centered binomial distribution CBD_eta */
    for (int i = 0; i < DLPL_N; i++) {
        uint32_t bits = prng_random32();
        int32_t a = 0, b = 0;
        
        for (int j = 0; j < eta; j++) {
            a += (bits >> j) & 1;
            b += (bits >> (eta + j)) & 1;
        }
        
        int32_t val = a - b;
        p->coeffs[i] = to_positive((poly_coeff_t)val);
    }
}

void gm_sample_uniform(general_matrix_t *m) {
    for (int i = 0; i < DLPL_K; i++) {
        for (int j = 0; j < DLPL_K; j++) {
            poly_sample_uniform(&m->blocks[i][j]);
        }
    }
}

void bc_sample_small(bc_matrix_t *m, int eta) {
    for (int i = 0; i < DLPL_K; i++) {
        poly_sample_cbd(&m->row[i], eta);
    }
}

int bc_sample_small_invertible(bc_matrix_t *m, int eta) {
    bc_matrix_t inv;
    const int max_attempts = 100;
    
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        bc_sample_small(m, eta);
        if (bc_inverse(&inv, m)) {
            return 1;
        }
    }
    return 0;
}

/* ==========================================================================
 * Hash Functions (Simplified - use proper implementation in production)
 * ========================================================================== */

/* Simple SHA-256 like hash (for demonstration) */
void hash_H(uint8_t out[32], const uint8_t *in, size_t inlen) {
    /* Simplified hash - use real SHA-256 in production */
    uint64_t state[4] = {
        0x6a09e667bb67ae85ULL,
        0x3c6ef372a54ff53aULL,
        0x510e527f9b05688cULL,
        0x1f83d9ab5be0cd19ULL
    };
    
    for (size_t i = 0; i < inlen; i++) {
        state[i % 4] ^= (uint64_t)in[i] << ((i % 8) * 8);
        state[(i + 1) % 4] = rotl(state[(i + 1) % 4], 13) ^ state[i % 4];
        state[(i + 2) % 4] += state[(i + 3) % 4];
    }
    
    /* Additional mixing */
    for (int r = 0; r < 20; r++) {
        for (int i = 0; i < 4; i++) {
            state[i] = rotl(state[i], 17) + state[(i + 1) % 4];
            state[(i + 2) % 4] ^= state[i];
        }
    }
    
    memcpy(out, state, 32);
}

void hash_G(bc_matrix_t *r, bc_matrix_t *d,
            const public_key_t *pk, const uint8_t msg[DLPL_MSG_BYTES]) {
    /* Derive (r, d) from (pk, msg) using XOF */
    uint8_t pk_bytes[DLPL_PK_BYTES];
    pk_to_bytes(pk_bytes, pk);
    
    /* Create seed from pk and msg */
    uint8_t seed[64];
    hash_H(seed, pk_bytes, DLPL_PK_BYTES);
    hash_H(seed + 32, msg, DLPL_MSG_BYTES);
    
    /* Use seed for deterministic sampling */
    prng_seed(seed);
    
    /* Sample r (must be invertible) */
    if (!bc_sample_small_invertible(r, DLPL_ETA_S)) {
        /* Fallback: just sample small */
        bc_sample_small(r, DLPL_ETA_S);
    }
    
    /* Sample d */
    bc_sample_small(d, DLPL_ETA_E);
    
    /* Restore random state (not strictly necessary) */
    prng_seed(NULL);
}

/* ==========================================================================
 * PKE Operations
 * ========================================================================== */

void dlpl_keygen(public_key_t *pk, secret_key_t *sk) {
    bc_matrix_t s_inv;
    general_matrix_t sA, sA_plus_e;
    
    /* Sample uniform random A */
    gm_sample_uniform(&pk->A);
    
    /* Sample small invertible s */
    if (!bc_sample_small_invertible(&sk->s, DLPL_ETA_S)) {
        /* Should not happen; handle error */
        return;
    }
    
    /* Sample small e */
    bc_sample_small(&sk->e, DLPL_ETA_E);
    
    /* Compute s^(-1) */
    bc_inverse(&s_inv, &sk->s);
    
    /* Compute sA */
    bc_mul_gm(&sA, &sk->s, &pk->A);
    
    /* Compute sA + e */
    gm_add_bc(&sA_plus_e, &sA, &sk->e);
    
    /* Compute t = (sA + e) * s^(-1) */
    gm_mul_bc(&pk->t, &sA_plus_e, &s_inv);
    
    /* Clean up */
    secure_zero(&s_inv, sizeof(s_inv));
}

void dlpl_encrypt(ciphertext_t *ct, 
                  const public_key_t *pk,
                  const uint8_t msg[DLPL_MSG_BYTES]) {
    bc_matrix_t r, d, r_inv;
    general_matrix_t rA, rA_plus_d, rt, rt_plus_d, shared;
    
    /* Derive (r, d) from G(pk, msg) */
    hash_G(&r, &d, pk, msg);
    
    /* Ensure r is invertible */
    if (!bc_inverse(&r_inv, &r)) {
        /* Re-sample if needed (should be rare) */
        bc_sample_small_invertible(&r, DLPL_ETA_S);
        bc_inverse(&r_inv, &r);
    }
    
    /* Compute u = (rA + d) * r^(-1) */
    bc_mul_gm(&rA, &r, &pk->A);
    gm_add_bc(&rA_plus_d, &rA, &d);
    gm_mul_bc(&ct->u, &rA_plus_d, &r_inv);
    
    /* Compute shared = (rt + d) * r^(-1) */
    bc_mul_gm(&rt, &r, &pk->t);
    gm_add_bc(&rt_plus_d, &rt, &d);
    gm_mul_bc(&shared, &rt_plus_d, &r_inv);
    
    /* Compute v = msg XOR H(shared) */
    uint8_t shared_bytes[DLPL_MATRIX_BYTES];
    uint8_t h[32];
    gm_to_bytes(shared_bytes, &shared);
    hash_H(h, shared_bytes, DLPL_MATRIX_BYTES);
    
    for (int i = 0; i < DLPL_MSG_BYTES; i++) {
        ct->v[i] = msg[i] ^ h[i];
    }
    
    /* Clean up sensitive data */
    secure_zero(&r, sizeof(r));
    secure_zero(&r_inv, sizeof(r_inv));
    secure_zero(&d, sizeof(d));
    secure_zero(&shared, sizeof(shared));
}

void dlpl_decrypt(uint8_t msg[DLPL_MSG_BYTES],
                  const ciphertext_t *ct,
                  const secret_key_t *sk) {
    bc_matrix_t s_inv;
    general_matrix_t su, su_plus_e, shared;
    
    /* Compute s^(-1) */
    bc_inverse(&s_inv, &sk->s);
    
    /* Compute su */
    bc_mul_gm(&su, &sk->s, &ct->u);
    
    /* Compute su + e */
    gm_add_bc(&su_plus_e, &su, &sk->e);
    
    /* Compute shared = (su + e) * s^(-1) */
    gm_mul_bc(&shared, &su_plus_e, &s_inv);
    
    /* Compute msg = v XOR H(shared) */
    uint8_t shared_bytes[DLPL_MATRIX_BYTES];
    uint8_t h[32];
    gm_to_bytes(shared_bytes, &shared);
    hash_H(h, shared_bytes, DLPL_MATRIX_BYTES);
    
    for (int i = 0; i < DLPL_MSG_BYTES; i++) {
        msg[i] = ct->v[i] ^ h[i];
    }
    
    /* Clean up */
    secure_zero(&s_inv, sizeof(s_inv));
    secure_zero(&shared, sizeof(shared));
}

void dlpl_decrypt_verify(uint8_t msg[DLPL_MSG_BYTES],
                         int *valid,
                         const ciphertext_t *ct,
                         const secret_key_t *sk,
                         const public_key_t *pk) {
    /* Decrypt */
    dlpl_decrypt(msg, ct, sk);
    
    /* Re-encrypt */
    ciphertext_t ct_check;
    dlpl_encrypt(&ct_check, pk, msg);
    
    /* Compare ciphertexts in constant time */
    uint8_t ct_bytes[DLPL_CT_BYTES];
    uint8_t ct_check_bytes[DLPL_CT_BYTES];
    ct_to_bytes(ct_bytes, ct);
    ct_to_bytes(ct_check_bytes, &ct_check);
    
    *valid = constant_time_compare(ct_bytes, ct_check_bytes, DLPL_CT_BYTES);
    
    /* If invalid, return random message */
    if (!*valid) {
        for (int i = 0; i < DLPL_MSG_BYTES; i++) {
            msg[i] = (uint8_t)prng_random32();
        }
    }
}

/* ==========================================================================
 * Serialization
 * ========================================================================== */

void pk_to_bytes(uint8_t out[DLPL_PK_BYTES], const public_key_t *pk) {
    gm_to_bytes(out, &pk->A);
    gm_to_bytes(out + DLPL_MATRIX_BYTES, &pk->t);
}

void pk_from_bytes(public_key_t *pk, const uint8_t in[DLPL_PK_BYTES]) {
    gm_from_bytes(&pk->A, in);
    gm_from_bytes(&pk->t, in + DLPL_MATRIX_BYTES);
}

void sk_to_bytes(uint8_t out[DLPL_SK_BYTES], const secret_key_t *sk) {
    bc_to_bytes(out, &sk->s);
    bc_to_bytes(out + DLPL_BC_BYTES, &sk->e);
}

void sk_from_bytes(secret_key_t *sk, const uint8_t in[DLPL_SK_BYTES]) {
    bc_from_bytes(&sk->s, in);
    bc_from_bytes(&sk->e, in + DLPL_BC_BYTES);
}

void ct_to_bytes(uint8_t out[DLPL_CT_BYTES], const ciphertext_t *ct) {
    gm_to_bytes(out, &ct->u);
    memcpy(out + DLPL_MATRIX_BYTES, ct->v, DLPL_MSG_BYTES);
}

void ct_from_bytes(ciphertext_t *ct, const uint8_t in[DLPL_CT_BYTES]) {
    gm_from_bytes(&ct->u, in);
    memcpy(ct->v, in + DLPL_MATRIX_BYTES, DLPL_MSG_BYTES);
}

/* ==========================================================================
 * Utility Functions
 * ========================================================================== */

void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

int ct_validate(const ciphertext_t *ct) {
    /* Check all coefficients are in valid range */
    for (int i = 0; i < DLPL_K; i++) {
        for (int j = 0; j < DLPL_K; j++) {
            for (int c = 0; c < DLPL_N; c++) {
                if (ct->u.blocks[i][j].coeffs[c] >= DLPL_Q) {
                    return 0;
                }
            }
        }
    }
    return 1;
}

void dlpl_get_sizes(size_t *pk_size, size_t *sk_size, size_t *ct_size) {
    if (pk_size) *pk_size = DLPL_PK_BYTES;
    if (sk_size) *sk_size = DLPL_SK_BYTES;
    if (ct_size) *ct_size = DLPL_CT_BYTES;
}

const char* dlpl_get_name(void) {
    return DLPL_NAME;
}
