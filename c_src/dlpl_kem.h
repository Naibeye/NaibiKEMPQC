/**
 * @file dlpl_kem.h
 * @brief DLPL-DH Key Encapsulation Mechanism (KEM)
 * 
 * Implements IND-CCA2 secure KEM using Fujisaki-Okamoto transform
 * applied to the underlying IND-CPA PKE scheme.
 */

#ifndef DLPL_KEM_H
#define DLPL_KEM_H

#include <stddef.h>
#include <stdint.h>
#include "dlpl_params.h"
#include "dlpl_poly.h"
#include "dlpl_pke.h"

/* ==========================================================================
 * KEM Parameters
 * ========================================================================== */

#define DLPL_KEM_SHARED_SECRET_BYTES  32
#define DLPL_KEM_COINS_BYTES          32

/* KEM key sizes include additional components for FO transform */
#define DLPL_KEM_PK_BYTES   DLPL_PK_BYTES
#define DLPL_KEM_SK_BYTES   (DLPL_SK_BYTES + DLPL_PK_BYTES + 32 + 32)  /* sk + pk + H(pk) + z */
#define DLPL_KEM_CT_BYTES   DLPL_CT_BYTES

/* ==========================================================================
 * KEM Key Structures
 * ========================================================================== */

/**
 * @brief KEM public key (same as PKE)
 */
typedef struct {
    public_key_t pke_pk;
} kem_public_key_t;

/**
 * @brief KEM secret key (extended for FO transform)
 * Contains: PKE secret key + public key copy + H(pk) + implicit rejection key z
 */
typedef struct {
    secret_key_t pke_sk;       /* PKE secret key (s, e) */
    public_key_t pke_pk;       /* Copy of public key for re-encryption */
    uint8_t pk_hash[32];       /* H(pk) - hash of public key */
    uint8_t z[32];             /* Implicit rejection key */
} kem_secret_key_t;

/**
 * @brief KEM ciphertext (same as PKE)
 */
typedef struct {
    ciphertext_t pke_ct;
} kem_ciphertext_t;

/* ==========================================================================
 * KEM Operations
 * ========================================================================== */

/**
 * @brief Generate KEM key pair
 * 
 * @param pk Output public key
 * @param sk Output secret key (includes pk copy and z)
 */
void dlpl_kem_keygen(kem_public_key_t *pk, kem_secret_key_t *sk);

/**
 * @brief Encapsulate: generate shared secret and ciphertext
 * 
 * FO Encapsulation:
 *   1. m ← random
 *   2. (K, r) = G(m || pk)
 *   3. c = Enc(pk, m; r)
 *   4. K' = H(K || c)
 * 
 * @param ct Output ciphertext
 * @param ss Output shared secret (32 bytes)
 * @param pk Public key
 */
void dlpl_kem_encaps(kem_ciphertext_t *ct,
                     uint8_t ss[DLPL_KEM_SHARED_SECRET_BYTES],
                     const kem_public_key_t *pk);

/**
 * @brief Decapsulate: recover shared secret from ciphertext
 * 
 * FO Decapsulation with implicit rejection:
 *   1. m' = Dec(sk, c)
 *   2. (K, r) = G(m' || pk)
 *   3. c' = Enc(pk, m'; r)
 *   4. if c == c': K' = H(K || c)
 *      else:       K' = H(z || c)
 * 
 * @param ss Output shared secret (32 bytes)
 * @param ct Ciphertext
 * @param sk Secret key
 */
void dlpl_kem_decaps(uint8_t ss[DLPL_KEM_SHARED_SECRET_BYTES],
                     const kem_ciphertext_t *ct,
                     const kem_secret_key_t *sk);

/* ==========================================================================
 * Serialization
 * ========================================================================== */

/**
 * @brief Serialize KEM public key to bytes
 */
void kem_pk_to_bytes(uint8_t out[DLPL_KEM_PK_BYTES], const kem_public_key_t *pk);

/**
 * @brief Deserialize KEM public key from bytes
 */
void kem_pk_from_bytes(kem_public_key_t *pk, const uint8_t in[DLPL_KEM_PK_BYTES]);

/**
 * @brief Serialize KEM secret key to bytes
 */
void kem_sk_to_bytes(uint8_t out[DLPL_KEM_SK_BYTES], const kem_secret_key_t *sk);

/**
 * @brief Deserialize KEM secret key from bytes
 */
void kem_sk_from_bytes(kem_secret_key_t *sk, const uint8_t in[DLPL_KEM_SK_BYTES]);

/**
 * @brief Serialize KEM ciphertext to bytes
 */
void kem_ct_to_bytes(uint8_t out[DLPL_KEM_CT_BYTES], const kem_ciphertext_t *ct);

/**
 * @brief Deserialize KEM ciphertext from bytes
 */
void kem_ct_from_bytes(kem_ciphertext_t *ct, const uint8_t in[DLPL_KEM_CT_BYTES]);

/* ==========================================================================
 * Hash Functions for KEM
 * ========================================================================== */

/**
 * @brief Hash function G: (m || pk) -> (K, coins)
 * Uses SHAKE-256 for domain separation
 */
void kem_hash_G(uint8_t K[32], uint8_t coins[32],
                const uint8_t m[32], const uint8_t pk[DLPL_KEM_PK_BYTES]);

/**
 * @brief Hash function H: data -> 32 bytes
 * Uses SHA3-256
 */
void kem_hash_H(uint8_t out[32], const uint8_t *data, size_t len);

/* ==========================================================================
 * Utility
 * ========================================================================== */

/**
 * @brief Get KEM sizes
 */
void dlpl_kem_get_sizes(size_t *pk_size, size_t *sk_size, 
                        size_t *ct_size, size_t *ss_size);

/**
 * @brief Get KEM name
 */
const char* dlpl_kem_get_name(void);

#endif /* DLPL_KEM_H */
