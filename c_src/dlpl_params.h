/**
 * @file dlpl_params.h
 * @brief Parameter definitions for DLPL-DH PKE scheme
 * 
 * NIST Security Levels:
 * - L1: 128-bit security
 * - L3: 192-bit security  
 * - L5: 256-bit security
 */

#ifndef DLPL_PARAMS_H
#define DLPL_PARAMS_H

#include <stdint.h>

/* ==========================================================================
 * Security Level Selection (compile-time)
 * Define one of: DLPL_LEVEL_TOY, DLPL_LEVEL_1, DLPL_LEVEL_3, DLPL_LEVEL_5
 * ========================================================================== */

#ifndef DLPL_SECURITY_LEVEL
#define DLPL_SECURITY_LEVEL 1  /* Default to L1 */
#endif

/* ==========================================================================
 * Parameter Sets
 * ========================================================================== */

#if DLPL_SECURITY_LEVEL == 0  /* Toy parameters for testing */
    #define DLPL_N          64      /* Polynomial degree */
    #define DLPL_Q          257     /* Prime modulus (NTT-friendly: 257 ≡ 1 mod 128) */
    #define DLPL_K          2       /* Block-circulant dimension */
    #define DLPL_ETA_S      2       /* Secret distribution bound */
    #define DLPL_ETA_E      2       /* Error distribution bound */
    #define DLPL_LOGQ       9       /* ceil(log2(q)) */
    #define DLPL_NAME       "DLPL-Toy"

#elif DLPL_SECURITY_LEVEL == 1  /* NIST Level 1 (128-bit) */
    #define DLPL_N          128     /* Polynomial degree */
    #define DLPL_Q          3329    /* Prime modulus (Kyber: 3329 ≡ 1 mod 256) */
    #define DLPL_K          2       /* Block-circulant dimension */
    #define DLPL_ETA_S      3       /* Secret distribution bound */
    #define DLPL_ETA_E      3       /* Error distribution bound */
    #define DLPL_LOGQ       12      /* ceil(log2(q)) */
    #define DLPL_NAME       "DLPL-256"

#elif DLPL_SECURITY_LEVEL == 3  /* NIST Level 3 (192-bit) */
    #define DLPL_N          128     /* Polynomial degree */
    #define DLPL_Q          3329    /* Prime modulus (Kyber: 3329 ≡ 1 mod 256) */
    #define DLPL_K          3       /* Block-circulant dimension */
    #define DLPL_ETA_S      2       /* Secret distribution bound */
    #define DLPL_ETA_E      2       /* Error distribution bound */
    #define DLPL_LOGQ       12      /* ceil(log2(q)) */
    #define DLPL_NAME       "DLPL-384"

#elif DLPL_SECURITY_LEVEL == 5  /* NIST Level 5 (256-bit) */
    #define DLPL_N          256     /* Polynomial degree */
    #define DLPL_Q          7681    /* Prime modulus (7681 ≡ 1 mod 512, NewHope) */
    #define DLPL_K          3       /* Block-circulant dimension */
    #define DLPL_ETA_S      2       /* Secret distribution bound */
    #define DLPL_ETA_E      2       /* Error distribution bound */
    #define DLPL_LOGQ       13      /* ceil(log2(q)) */
    #define DLPL_NAME       "DLPL-768"

#else
    #error "Invalid DLPL_SECURITY_LEVEL. Choose 0 (toy), 1, 3, or 5."
#endif

/* ==========================================================================
 * Derived Parameters
 * ========================================================================== */

/* Size calculations */
#define DLPL_POLY_BYTES     (DLPL_N * sizeof(int16_t))
#define DLPL_BC_ELEMENTS    (DLPL_K)
#define DLPL_BC_BYTES       (DLPL_K * DLPL_POLY_BYTES)
#define DLPL_MATRIX_BLOCKS  (DLPL_K * DLPL_K)
#define DLPL_MATRIX_BYTES   (DLPL_MATRIX_BLOCKS * DLPL_POLY_BYTES)

/* Message size */
#define DLPL_MSG_BYTES      32

/* Key sizes */
#define DLPL_PK_BYTES       (2 * DLPL_MATRIX_BYTES)  /* A and t */
#define DLPL_SK_BYTES       (2 * DLPL_BC_BYTES)      /* s and e */
#define DLPL_CT_BYTES       (DLPL_MATRIX_BYTES + DLPL_MSG_BYTES)  /* u and v */

/* NTT parameters */
#define DLPL_NTT_ORDER      (2 * DLPL_N)  /* Order for 2n-th root of unity */

/* ==========================================================================
 * Type Definitions
 * ========================================================================== */

typedef int16_t poly_coeff_t;      /* Polynomial coefficient type */
typedef int32_t poly_wide_t;       /* Wide type for multiplication */
typedef int64_t poly_acc_t;        /* Accumulator type for reductions */

/* Polynomial in R_q */
typedef struct {
    poly_coeff_t coeffs[DLPL_N];
} poly_t;

/* Block-circulant matrix (stored as first row) */
typedef struct {
    poly_t row[DLPL_K];
} bc_matrix_t;

/* General k×k matrix over R_q */
typedef struct {
    poly_t blocks[DLPL_K][DLPL_K];
} general_matrix_t;

/* Public key: (A, t) */
typedef struct {
    general_matrix_t A;
    general_matrix_t t;
} public_key_t;

/* Secret key: (s, e) */
typedef struct {
    bc_matrix_t s;
    bc_matrix_t e;
} secret_key_t;

/* Ciphertext: (u, v) */
typedef struct {
    general_matrix_t u;
    uint8_t v[DLPL_MSG_BYTES];
} ciphertext_t;

#endif /* DLPL_PARAMS_H */
