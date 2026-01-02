/**
 * @file dlpl_poly.h
 * @brief Polynomial and matrix operations for DLPL-DH PKE
 */

#ifndef DLPL_POLY_H
#define DLPL_POLY_H

#include "dlpl_params.h"
#include "dlpl_ntt.h"

/* ==========================================================================
 * Polynomial Operations
 * ========================================================================== */

/**
 * @brief Set polynomial to zero
 */
void poly_zero(poly_t *p);

/**
 * @brief Set polynomial to one (constant 1)
 */
void poly_one(poly_t *p);

/**
 * @brief Copy polynomial
 */
void poly_copy(poly_t *dest, const poly_t *src);

/**
 * @brief Add two polynomials: r = a + b mod q
 */
void poly_add(poly_t *r, const poly_t *a, const poly_t *b);

/**
 * @brief Subtract two polynomials: r = a - b mod q
 */
void poly_sub(poly_t *r, const poly_t *a, const poly_t *b);

/**
 * @brief Negate polynomial: r = -a mod q
 */
void poly_neg(poly_t *r, const poly_t *a);

/**
 * @brief Multiply polynomial by scalar: r = a * s mod q
 */
void poly_scalar_mul(poly_t *r, const poly_t *a, poly_coeff_t s);

/**
 * @brief Reduce all coefficients to [0, q-1]
 */
void poly_reduce(poly_t *p);

/**
 * @brief Compute infinity norm (max absolute centered coefficient)
 */
int16_t poly_norm_inf(const poly_t *p);

/**
 * @brief Check if two polynomials are equal (constant-time)
 */
int poly_equal(const poly_t *a, const poly_t *b);

/**
 * @brief Compute polynomial inverse in R_q using extended GCD
 * @return 1 if invertible, 0 otherwise
 */
int poly_inverse(poly_t *r, const poly_t *a);

/* ==========================================================================
 * Block-Circulant Matrix Operations
 * ========================================================================== */

/**
 * @brief Set block-circulant matrix to zero
 */
void bc_zero(bc_matrix_t *m);

/**
 * @brief Set block-circulant matrix to identity
 */
void bc_identity(bc_matrix_t *m);

/**
 * @brief Copy block-circulant matrix
 */
void bc_copy(bc_matrix_t *dest, const bc_matrix_t *src);

/**
 * @brief Get (i,j) block of block-circulant matrix
 * Block-circulant: M[i][j] = row[(j-i) mod k]
 */
void bc_get_block(poly_t *p, const bc_matrix_t *m, int i, int j);

/**
 * @brief Add two block-circulant matrices: r = a + b
 */
void bc_add(bc_matrix_t *r, const bc_matrix_t *a, const bc_matrix_t *b);

/**
 * @brief Subtract block-circulant matrices: r = a - b
 */
void bc_sub(bc_matrix_t *r, const bc_matrix_t *a, const bc_matrix_t *b);

/**
 * @brief Multiply two block-circulant matrices: r = a * b
 */
void bc_mul(bc_matrix_t *r, const bc_matrix_t *a, const bc_matrix_t *b);

/**
 * @brief Negate block-circulant matrix: r = -a
 */
void bc_neg(bc_matrix_t *r, const bc_matrix_t *a);

/**
 * @brief Compute inverse of block-circulant matrix
 * @return 1 if invertible, 0 otherwise
 */
int bc_inverse(bc_matrix_t *r, const bc_matrix_t *a);

/**
 * @brief Compute inverse with random blinding for side-channel protection
 */
int bc_inverse_blinded(bc_matrix_t *r, const bc_matrix_t *a);

/* ==========================================================================
 * General Matrix Operations
 * ========================================================================== */

/**
 * @brief Set general matrix to zero
 */
void gm_zero(general_matrix_t *m);

/**
 * @brief Set general matrix to identity
 */
void gm_identity(general_matrix_t *m);

/**
 * @brief Copy general matrix
 */
void gm_copy(general_matrix_t *dest, const general_matrix_t *src);

/**
 * @brief Add general matrix and block-circulant: r = a + b
 */
void gm_add_bc(general_matrix_t *r, const general_matrix_t *a, const bc_matrix_t *b);

/**
 * @brief Subtract block-circulant from general matrix: r = a - b
 */
void gm_sub_bc(general_matrix_t *r, const general_matrix_t *a, const bc_matrix_t *b);

/**
 * @brief Multiply general matrices: r = a * b
 */
void gm_mul(general_matrix_t *r, const general_matrix_t *a, const general_matrix_t *b);

/**
 * @brief Multiply block-circulant by general matrix: r = bc * gm
 * Result is a general matrix
 */
void bc_mul_gm(general_matrix_t *r, const bc_matrix_t *bc, const general_matrix_t *gm);

/**
 * @brief Multiply general matrix by block-circulant: r = gm * bc
 * Result is a general matrix
 */
void gm_mul_bc(general_matrix_t *r, const general_matrix_t *gm, const bc_matrix_t *bc);

/**
 * @brief Add two general matrices: r = a + b
 */
void gm_add(general_matrix_t *r, const general_matrix_t *a, const general_matrix_t *b);

/**
 * @brief Subtract general matrices: r = a - b
 */
void gm_sub(general_matrix_t *r, const general_matrix_t *a, const general_matrix_t *b);

/* ==========================================================================
 * Serialization
 * ========================================================================== */

/**
 * @brief Serialize polynomial to bytes
 */
void poly_to_bytes(uint8_t *out, const poly_t *p);

/**
 * @brief Deserialize polynomial from bytes
 */
void poly_from_bytes(poly_t *p, const uint8_t *in);

/**
 * @brief Serialize block-circulant matrix to bytes
 */
void bc_to_bytes(uint8_t *out, const bc_matrix_t *m);

/**
 * @brief Deserialize block-circulant matrix from bytes
 */
void bc_from_bytes(bc_matrix_t *m, const uint8_t *in);

/**
 * @brief Serialize general matrix to bytes
 */
void gm_to_bytes(uint8_t *out, const general_matrix_t *m);

/**
 * @brief Deserialize general matrix from bytes
 */
void gm_from_bytes(general_matrix_t *m, const uint8_t *in);

#endif /* DLPL_POLY_H */
