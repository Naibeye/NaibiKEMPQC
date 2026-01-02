/**
 * @file dlpl_kem.c
 * @brief DLPL-DH Key Encapsulation Mechanism implementation
 */

#include "dlpl_kem.h"
#include "dlpl_pke.h"
#include "dlpl_ntt.h"
#include <string.h>
#include <stdlib.h>

/* Simple SHAKE-256 / SHA3-256 implementation for portability */
/* For production, use a proper crypto library */

/* Keccak constants */
static const uint64_t keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccak_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccak_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static void keccak_f(uint64_t st[25]) {
    uint64_t t, bc[5];
    
    for (int r = 0; r < 24; r++) {
        /* Theta */
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }
        
        /* Rho Pi */
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = keccak_piln[i];
            bc[0] = st[j];
            st[j] = rotl64(t, keccak_rotc[i]);
            t = bc[0];
        }
        
        /* Chi */
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (int i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        
        /* Iota */
        st[0] ^= keccak_rc[r];
    }
}

/* SHA3-256 */
static void sha3_256(uint8_t out[32], const uint8_t *in, size_t inlen) {
    uint64_t st[25] = {0};
    size_t rate = 136;  /* (1600 - 256*2) / 8 */
    uint8_t temp[136];
    
    /* Absorb */
    while (inlen >= rate) {
        for (size_t i = 0; i < rate / 8; i++)
            st[i] ^= ((uint64_t*)in)[i];
        keccak_f(st);
        in += rate;
        inlen -= rate;
    }
    
    /* Padding */
    memset(temp, 0, rate);
    memcpy(temp, in, inlen);
    temp[inlen] = 0x06;      /* SHA3 domain separator */
    temp[rate - 1] |= 0x80;  /* Final bit */
    
    for (size_t i = 0; i < rate / 8; i++)
        st[i] ^= ((uint64_t*)temp)[i];
    keccak_f(st);
    
    /* Squeeze */
    memcpy(out, st, 32);
}

/* SHAKE-256 */
static void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    uint64_t st[25] = {0};
    size_t rate = 136;  /* (1600 - 256*2) / 8 */
    uint8_t temp[136];
    
    /* Absorb */
    while (inlen >= rate) {
        for (size_t i = 0; i < rate / 8; i++)
            st[i] ^= ((uint64_t*)in)[i];
        keccak_f(st);
        in += rate;
        inlen -= rate;
    }
    
    /* Padding */
    memset(temp, 0, rate);
    memcpy(temp, in, inlen);
    temp[inlen] = 0x1f;      /* SHAKE domain separator */
    temp[rate - 1] |= 0x80;  /* Final bit */
    
    for (size_t i = 0; i < rate / 8; i++)
        st[i] ^= ((uint64_t*)temp)[i];
    keccak_f(st);
    
    /* Squeeze */
    while (outlen >= rate) {
        memcpy(out, st, rate);
        keccak_f(st);
        out += rate;
        outlen -= rate;
    }
    if (outlen > 0) {
        memcpy(out, st, outlen);
    }
}

/* ==========================================================================
 * Hash Functions for KEM
 * ========================================================================== */

void kem_hash_G(uint8_t K[32], uint8_t coins[32],
                const uint8_t m[32], const uint8_t pk[DLPL_KEM_PK_BYTES]) {
    /* G: (m || pk) -> (K, coins) using SHAKE-256 */
    size_t input_len = 32 + DLPL_KEM_PK_BYTES;
    uint8_t *input = malloc(input_len);
    uint8_t output[64];
    
    memcpy(input, m, 32);
    memcpy(input + 32, pk, DLPL_KEM_PK_BYTES);
    
    shake256(output, 64, input, input_len);
    
    memcpy(K, output, 32);
    memcpy(coins, output + 32, 32);
    
    secure_zero(input, input_len);
    free(input);
}

void kem_hash_H(uint8_t out[32], const uint8_t *data, size_t len) {
    sha3_256(out, data, len);
}

/* ==========================================================================
 * Deterministic Sampling (using coins as seed)
 * ========================================================================== */

/* Simple seeded PRNG for deterministic sampling */
typedef struct {
    uint8_t state[64];
    size_t pos;
} seeded_prng_t;

static void seeded_prng_init(seeded_prng_t *prng, const uint8_t seed[32]) {
    shake256(prng->state, 64, seed, 32);
    prng->pos = 0;
}

static uint8_t seeded_prng_byte(seeded_prng_t *prng) {
    if (prng->pos >= 64) {
        shake256(prng->state, 64, prng->state, 64);
        prng->pos = 0;
    }
    return prng->state[prng->pos++];
}

static int16_t seeded_sample_cbd(seeded_prng_t *prng, int eta) {
    int16_t a = 0, b = 0;
    for (int i = 0; i < eta; i++) {
        uint8_t byte = seeded_prng_byte(prng);
        a += (byte & 1);
        b += ((byte >> 1) & 1);
    }
    return a - b;
}

static void poly_sample_cbd_seeded(poly_t *p, seeded_prng_t *prng, int eta) {
    for (int i = 0; i < DLPL_N; i++) {
        p->coeffs[i] = seeded_sample_cbd(prng, eta);
        if (p->coeffs[i] < 0) p->coeffs[i] += DLPL_Q;
    }
}

static void bc_sample_small_seeded(bc_matrix_t *m, seeded_prng_t *prng, int eta) {
    for (int i = 0; i < DLPL_K; i++) {
        poly_sample_cbd_seeded(&m->row[i], prng, eta);
    }
}

static int bc_sample_small_invertible_seeded(bc_matrix_t *m, bc_matrix_t *m_inv, seeded_prng_t *prng, int eta) {
    for (int attempt = 0; attempt < 100; attempt++) {
        bc_sample_small_seeded(m, prng, eta);
        if (bc_inverse(m_inv, m) == 0) {
            return 1;  /* Success - m_inv now contains the inverse */
        }
    }
    return 0;  /* Failed */
}

/* ==========================================================================
 * KEM Operations
 * ========================================================================== */

void dlpl_kem_keygen(kem_public_key_t *pk, kem_secret_key_t *sk) {
    /* Generate underlying PKE key pair */
    dlpl_keygen(&pk->pke_pk, &sk->pke_sk);
    
    /* Copy public key into secret key (for re-encryption in decaps) */
    memcpy(&sk->pke_pk, &pk->pke_pk, sizeof(public_key_t));
    
    /* Compute H(pk) */
    uint8_t pk_bytes[DLPL_KEM_PK_BYTES];
    kem_pk_to_bytes(pk_bytes, pk);
    kem_hash_H(sk->pk_hash, pk_bytes, DLPL_KEM_PK_BYTES);
    
    /* Generate implicit rejection key z */
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        seed[i] = (uint8_t)rand();  /* In production, use secure random */
    }
    memcpy(sk->z, seed, 32);
}

void dlpl_kem_encaps(kem_ciphertext_t *ct,
                     uint8_t ss[DLPL_KEM_SHARED_SECRET_BYTES],
                     const kem_public_key_t *pk) {
    uint8_t m[32];
    uint8_t K[32];
    uint8_t pk_bytes[DLPL_KEM_PK_BYTES];
    uint8_t ct_bytes[DLPL_KEM_CT_BYTES];
    uint8_t hash_input[32 + DLPL_KEM_CT_BYTES];
    
    /* Sample random message m */
    for (int i = 0; i < 32; i++) {
        m[i] = (uint8_t)rand();  /* In production, use secure random */
    }
    
    /* Serialize pk for hashing */
    kem_pk_to_bytes(pk_bytes, pk);
    
    /* K = H(m || pk) - derive shared secret key */
    uint8_t m_pk[32 + DLPL_KEM_PK_BYTES];
    memcpy(m_pk, m, 32);
    memcpy(m_pk + 32, pk_bytes, DLPL_KEM_PK_BYTES);
    kem_hash_H(K, m_pk, 32 + DLPL_KEM_PK_BYTES);
    
    /* c = Enc(pk, m) - dlpl_encrypt is deterministic via hash_G(pk, m) */
    dlpl_encrypt(&ct->pke_ct, &pk->pke_pk, m);
    
    /* Serialize ciphertext */
    kem_ct_to_bytes(ct_bytes, ct);
    
    /* K' = H(K || c) */
    memcpy(hash_input, K, 32);
    memcpy(hash_input + 32, ct_bytes, DLPL_KEM_CT_BYTES);
    kem_hash_H(ss, hash_input, 32 + DLPL_KEM_CT_BYTES);
    
    /* Cleanup */
    secure_zero(m, 32);
    secure_zero(K, 32);
}

void dlpl_kem_decaps(uint8_t ss[DLPL_KEM_SHARED_SECRET_BYTES],
                     const kem_ciphertext_t *ct,
                     const kem_secret_key_t *sk) {
    uint8_t m_prime[32];
    uint8_t K[32];
    uint8_t pk_bytes[DLPL_KEM_PK_BYTES];
    uint8_t ct_bytes[DLPL_KEM_CT_BYTES];
    uint8_t ct_prime_bytes[DLPL_KEM_CT_BYTES];
    ciphertext_t ct_prime;
    uint8_t hash_input_valid[32 + DLPL_KEM_CT_BYTES];
    uint8_t hash_input_invalid[32 + DLPL_KEM_CT_BYTES];
    uint8_t K_valid[32], K_invalid[32];
    
    /* Decrypt to get m' */
    dlpl_decrypt(m_prime, &ct->pke_ct, &sk->pke_sk);
    
    /* Serialize pk */
    pk_to_bytes(pk_bytes, &sk->pke_pk);
    
    /* K = H(m' || pk) */
    uint8_t m_pk[32 + DLPL_KEM_PK_BYTES];
    memcpy(m_pk, m_prime, 32);
    memcpy(m_pk + 32, pk_bytes, DLPL_KEM_PK_BYTES);
    kem_hash_H(K, m_pk, 32 + DLPL_KEM_PK_BYTES);
    
    /* c' = Enc(pk, m') - dlpl_encrypt is deterministic via hash_G(pk, m') */
    dlpl_encrypt(&ct_prime, &sk->pke_pk, m_prime);
    
    /* Serialize both ciphertexts */
    kem_ct_to_bytes(ct_bytes, ct);
    ct_to_bytes(ct_prime_bytes, &ct_prime);
    
    /* Compare c and c' in constant time */
    int ct_match = constant_time_compare(ct_bytes, ct_prime_bytes, DLPL_KEM_CT_BYTES);
    
    /* Compute K_valid = H(K || c) */
    memcpy(hash_input_valid, K, 32);
    memcpy(hash_input_valid + 32, ct_bytes, DLPL_KEM_CT_BYTES);
    kem_hash_H(K_valid, hash_input_valid, 32 + DLPL_KEM_CT_BYTES);
    
    /* Compute K_invalid = H(z || c) */
    memcpy(hash_input_invalid, sk->z, 32);
    memcpy(hash_input_invalid + 32, ct_bytes, DLPL_KEM_CT_BYTES);
    kem_hash_H(K_invalid, hash_input_invalid, 32 + DLPL_KEM_CT_BYTES);
    
    /* Constant-time selection: if ct_match then K_valid else K_invalid */
    uint8_t mask = (uint8_t)(-(int8_t)ct_match);  /* 0xFF if match, 0x00 otherwise */
    for (int i = 0; i < 32; i++) {
        ss[i] = (K_valid[i] & mask) | (K_invalid[i] & ~mask);
    }
    
    /* Cleanup */
    secure_zero(m_prime, 32);
    secure_zero(K, 32);
    secure_zero(K_valid, 32);
    secure_zero(K_invalid, 32);
}

/* ==========================================================================
 * Serialization
 * ========================================================================== */

void kem_pk_to_bytes(uint8_t out[DLPL_KEM_PK_BYTES], const kem_public_key_t *pk) {
    pk_to_bytes(out, &pk->pke_pk);
}

void kem_pk_from_bytes(kem_public_key_t *pk, const uint8_t in[DLPL_KEM_PK_BYTES]) {
    pk_from_bytes(&pk->pke_pk, in);
}

void kem_sk_to_bytes(uint8_t out[DLPL_KEM_SK_BYTES], const kem_secret_key_t *sk) {
    size_t offset = 0;
    
    /* PKE secret key */
    sk_to_bytes(out + offset, &sk->pke_sk);
    offset += DLPL_SK_BYTES;
    
    /* PKE public key */
    pk_to_bytes(out + offset, &sk->pke_pk);
    offset += DLPL_PK_BYTES;
    
    /* H(pk) */
    memcpy(out + offset, sk->pk_hash, 32);
    offset += 32;
    
    /* z */
    memcpy(out + offset, sk->z, 32);
}

void kem_sk_from_bytes(kem_secret_key_t *sk, const uint8_t in[DLPL_KEM_SK_BYTES]) {
    size_t offset = 0;
    
    /* PKE secret key */
    sk_from_bytes(&sk->pke_sk, in + offset);
    offset += DLPL_SK_BYTES;
    
    /* PKE public key */
    pk_from_bytes(&sk->pke_pk, in + offset);
    offset += DLPL_PK_BYTES;
    
    /* H(pk) */
    memcpy(sk->pk_hash, in + offset, 32);
    offset += 32;
    
    /* z */
    memcpy(sk->z, in + offset, 32);
}

void kem_ct_to_bytes(uint8_t out[DLPL_KEM_CT_BYTES], const kem_ciphertext_t *ct) {
    ct_to_bytes(out, &ct->pke_ct);
}

void kem_ct_from_bytes(kem_ciphertext_t *ct, const uint8_t in[DLPL_KEM_CT_BYTES]) {
    ct_from_bytes(&ct->pke_ct, in);
}

/* ==========================================================================
 * Utility
 * ========================================================================== */

void dlpl_kem_get_sizes(size_t *pk_size, size_t *sk_size, 
                        size_t *ct_size, size_t *ss_size) {
    if (pk_size) *pk_size = DLPL_KEM_PK_BYTES;
    if (sk_size) *sk_size = DLPL_KEM_SK_BYTES;
    if (ct_size) *ct_size = DLPL_KEM_CT_BYTES;
    if (ss_size) *ss_size = DLPL_KEM_SHARED_SECRET_BYTES;
}

const char* dlpl_kem_get_name(void) {
    return DLPL_NAME "-KEM";
}
