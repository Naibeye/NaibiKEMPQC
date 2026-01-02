/**
 * @file dlpl_pke.h
 * @brief DLPL-DH Public Key Encryption scheme
 */

#ifndef DLPL_PKE_H
#define DLPL_PKE_H

#include <stddef.h>
#include <stdio.h>
#include "dlpl_params.h"
#include "dlpl_poly.h"

/* ==========================================================================
 * Random Sampling
 * ========================================================================== */

/**
 * @brief Initialize random number generator
 * @param seed 32-byte seed (NULL for system random)
 */
void dlpl_random_init(const uint8_t seed[32]);

/**
 * @brief Sample uniform random polynomial
 */
void poly_sample_uniform(poly_t *p);

/**
 * @brief Sample small polynomial using centered binomial distribution
 * @param p Output polynomial
 * @param eta CBD parameter
 */
void poly_sample_cbd(poly_t *p, int eta);

/**
 * @brief Sample uniform random general matrix
 */
void gm_sample_uniform(general_matrix_t *m);

/**
 * @brief Sample small block-circulant matrix
 */
void bc_sample_small(bc_matrix_t *m, int eta);

/**
 * @brief Sample small invertible block-circulant matrix
 * @return 1 on success, 0 on failure after max attempts
 */
int bc_sample_small_invertible(bc_matrix_t *m, int eta);

/* ==========================================================================
 * Hash Functions
 * ========================================================================== */

/**
 * @brief Hash function H: bytes -> 32 bytes (SHA-256)
 */
void hash_H(uint8_t out[32], const uint8_t *in, size_t inlen);

/**
 * @brief Expandable hash function G for (r, d) derivation (SHAKE-256)
 */
void hash_G(bc_matrix_t *r, bc_matrix_t *d,
            const public_key_t *pk, const uint8_t msg[DLPL_MSG_BYTES]);

/* ==========================================================================
 * PKE Operations
 * ========================================================================== */

/**
 * @brief Generate public and secret keys
 * @param pk Output public key
 * @param sk Output secret key
 */
void dlpl_keygen(public_key_t *pk, secret_key_t *sk);

/**
 * @brief Encrypt a message
 * @param ct Output ciphertext
 * @param pk Public key
 * @param msg Message (32 bytes)
 */
void dlpl_encrypt(ciphertext_t *ct, 
                  const public_key_t *pk,
                  const uint8_t msg[DLPL_MSG_BYTES]);

/**
 * @brief Decrypt a ciphertext
 * @param msg Output message (32 bytes)
 * @param ct Ciphertext
 * @param sk Secret key
 */
void dlpl_decrypt(uint8_t msg[DLPL_MSG_BYTES],
                  const ciphertext_t *ct,
                  const secret_key_t *sk);

/**
 * @brief Decrypt with re-encryption verification (FO transform)
 * @param msg Output message (32 bytes)
 * @param valid Output validity flag (1 = valid, 0 = invalid)
 * @param ct Ciphertext
 * @param sk Secret key
 * @param pk Public key (for re-encryption)
 */
void dlpl_decrypt_verify(uint8_t msg[DLPL_MSG_BYTES],
                         int *valid,
                         const ciphertext_t *ct,
                         const secret_key_t *sk,
                         const public_key_t *pk);

/* ==========================================================================
 * Serialization
 * ========================================================================== */

/**
 * @brief Serialize public key to bytes
 */
void pk_to_bytes(uint8_t out[DLPL_PK_BYTES], const public_key_t *pk);

/**
 * @brief Deserialize public key from bytes
 */
void pk_from_bytes(public_key_t *pk, const uint8_t in[DLPL_PK_BYTES]);

/**
 * @brief Serialize secret key to bytes
 */
void sk_to_bytes(uint8_t out[DLPL_SK_BYTES], const secret_key_t *sk);

/**
 * @brief Deserialize secret key from bytes
 */
void sk_from_bytes(secret_key_t *sk, const uint8_t in[DLPL_SK_BYTES]);

/**
 * @brief Serialize ciphertext to bytes
 */
void ct_to_bytes(uint8_t out[DLPL_CT_BYTES], const ciphertext_t *ct);

/**
 * @brief Deserialize ciphertext from bytes
 */
void ct_from_bytes(ciphertext_t *ct, const uint8_t in[DLPL_CT_BYTES]);

/* ==========================================================================
 * Utility Functions
 * ========================================================================== */

/**
 * @brief Securely zero memory
 */
void secure_zero(void *ptr, size_t len);

/**
 * @brief Constant-time byte comparison
 * @return 1 if equal, 0 if not
 */
int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * @brief Validate ciphertext (range checks)
 * @return 1 if valid, 0 if invalid
 */
int ct_validate(const ciphertext_t *ct);

/**
 * @brief Get key and ciphertext sizes
 */
void dlpl_get_sizes(size_t *pk_size, size_t *sk_size, size_t *ct_size);

/**
 * @brief Get parameter name string
 */
const char* dlpl_get_name(void);

#endif /* DLPL_PKE_H */
