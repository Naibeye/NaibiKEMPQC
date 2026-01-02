/**
 * @file test_dlpl.c
 * @brief Test program for DLPL-DH PKE scheme
 */

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dlpl_pke.h"

/* ==========================================================================
 * Test Utilities
 * ========================================================================== */

#define TEST_ITERATIONS 100

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s\n", msg); \
        tests_failed++; \
        return 0; \
    } \
} while (0)

#define TEST_START(name) do { \
    printf("Testing %s... ", name); \
    fflush(stdout); \
} while (0)

#define TEST_PASS() do { \
    printf("OK\n"); \
    tests_passed++; \
} while (0)

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

/* ==========================================================================
 * Unit Tests
 * ========================================================================== */

static int test_ntt_roundtrip(void) {
    TEST_START("NTT roundtrip");
    
    poly_t p, p_copy;
    poly_sample_uniform(&p);
    memcpy(&p_copy, &p, sizeof(p));
    
    ntt_forward(p.coeffs);
    ntt_inverse(p.coeffs);
    
    for (int i = 0; i < DLPL_N; i++) {
        TEST_ASSERT(p.coeffs[i] == p_copy.coeffs[i], "NTT roundtrip failed");
    }
    
    TEST_PASS();
    return 1;
}

static int test_poly_mul_ntt(void) {
    TEST_START("Polynomial multiplication via NTT");
    
    /* Test a * 1 = a */
    poly_t a, one, result;
    poly_sample_uniform(&a);
    poly_zero(&one);
    one.coeffs[0] = 1;
    
    poly_mul_ntt(&result, &a, &one);
    
    for (int i = 0; i < DLPL_N; i++) {
        TEST_ASSERT(result.coeffs[i] == a.coeffs[i], "a * 1 != a");
    }
    
    TEST_PASS();
    return 1;
}

static int test_bc_inverse(void) {
    TEST_START("Block-circulant matrix inverse");
    
    bc_matrix_t m, m_inv, identity;
    
    /* Sample small invertible matrix */
    TEST_ASSERT(bc_sample_small_invertible(&m, DLPL_ETA_S), "Failed to sample invertible");
    
    /* Compute inverse */
    TEST_ASSERT(bc_inverse(&m_inv, &m), "Inverse computation failed");
    
    /* Verify m * m_inv = I */
    bc_mul(&identity, &m, &m_inv);
    
    /* Check first block is identity-like */
    /* identity.row[0] should be [1, 0, 0, ...] */
    TEST_ASSERT(identity.row[0].coeffs[0] == 1, "Identity check failed");
    for (int i = 1; i < DLPL_N; i++) {
        TEST_ASSERT(identity.row[0].coeffs[i] == 0, "Identity check failed");
    }
    
    TEST_PASS();
    return 1;
}

static int test_keygen(void) {
    TEST_START("Key generation");
    
    public_key_t pk;
    secret_key_t sk;
    
    dlpl_keygen(&pk, &sk);
    
    /* Basic sanity checks */
    int nonzero_pk = 0, nonzero_sk = 0;
    for (int i = 0; i < DLPL_K; i++) {
        for (int j = 0; j < DLPL_N; j++) {
            if (pk.A.blocks[0][i].coeffs[j] != 0) nonzero_pk++;
            if (sk.s.row[i].coeffs[j] != 0) nonzero_sk++;
        }
    }
    
    TEST_ASSERT(nonzero_pk > 0, "Public key all zeros");
    TEST_ASSERT(nonzero_sk > 0, "Secret key all zeros");
    
    TEST_PASS();
    return 1;
}

static int test_encrypt_decrypt(void) {
    TEST_START("Encrypt/Decrypt");
    
    public_key_t pk;
    secret_key_t sk;
    ciphertext_t ct;
    uint8_t msg[DLPL_MSG_BYTES];
    uint8_t msg_dec[DLPL_MSG_BYTES];
    
    /* Generate keys */
    dlpl_keygen(&pk, &sk);
    
    /* Create random message */
    for (int i = 0; i < DLPL_MSG_BYTES; i++) {
        msg[i] = (uint8_t)(rand() & 0xFF);
    }
    
    /* Encrypt */
    dlpl_encrypt(&ct, &pk, msg);
    
    /* Decrypt */
    dlpl_decrypt(msg_dec, &ct, &sk);
    
    /* Verify */
    TEST_ASSERT(memcmp(msg, msg_dec, DLPL_MSG_BYTES) == 0, "Decryption failed");
    
    TEST_PASS();
    return 1;
}

static int test_encrypt_decrypt_multiple(void) {
    TEST_START("Multiple encrypt/decrypt");
    
    for (int iter = 0; iter < TEST_ITERATIONS; iter++) {
        public_key_t pk;
        secret_key_t sk;
        ciphertext_t ct;
        uint8_t msg[DLPL_MSG_BYTES];
        uint8_t msg_dec[DLPL_MSG_BYTES];
        
        dlpl_keygen(&pk, &sk);
        
        for (int i = 0; i < DLPL_MSG_BYTES; i++) {
            msg[i] = (uint8_t)(rand() & 0xFF);
        }
        
        dlpl_encrypt(&ct, &pk, msg);
        dlpl_decrypt(msg_dec, &ct, &sk);
        
        TEST_ASSERT(memcmp(msg, msg_dec, DLPL_MSG_BYTES) == 0, 
                    "Decryption failed in iteration");
    }
    
    TEST_PASS();
    return 1;
}

static int test_decrypt_verify(void) {
    TEST_START("Decrypt with verification");
    
    public_key_t pk;
    secret_key_t sk;
    ciphertext_t ct;
    uint8_t msg[DLPL_MSG_BYTES];
    uint8_t msg_dec[DLPL_MSG_BYTES];
    int valid;
    
    dlpl_keygen(&pk, &sk);
    
    for (int i = 0; i < DLPL_MSG_BYTES; i++) {
        msg[i] = (uint8_t)(rand() & 0xFF);
    }
    
    dlpl_encrypt(&ct, &pk, msg);
    dlpl_decrypt_verify(msg_dec, &valid, &ct, &sk, &pk);
    
    TEST_ASSERT(valid, "Valid ciphertext marked as invalid");
    TEST_ASSERT(memcmp(msg, msg_dec, DLPL_MSG_BYTES) == 0, "Decryption failed");
    
    TEST_PASS();
    return 1;
}

static int test_serialization(void) {
    TEST_START("Serialization");
    
    public_key_t pk, pk2;
    secret_key_t sk, sk2;
    ciphertext_t ct, ct2;
    uint8_t msg[DLPL_MSG_BYTES] = {0x01, 0x02, 0x03};
    
    uint8_t pk_bytes[DLPL_PK_BYTES];
    uint8_t sk_bytes[DLPL_SK_BYTES];
    uint8_t ct_bytes[DLPL_CT_BYTES];
    
    dlpl_keygen(&pk, &sk);
    dlpl_encrypt(&ct, &pk, msg);
    
    /* Serialize */
    pk_to_bytes(pk_bytes, &pk);
    sk_to_bytes(sk_bytes, &sk);
    ct_to_bytes(ct_bytes, &ct);
    
    /* Deserialize */
    pk_from_bytes(&pk2, pk_bytes);
    sk_from_bytes(&sk2, sk_bytes);
    ct_from_bytes(&ct2, ct_bytes);
    
    /* Verify roundtrip */
    uint8_t pk_bytes2[DLPL_PK_BYTES];
    uint8_t sk_bytes2[DLPL_SK_BYTES];
    uint8_t ct_bytes2[DLPL_CT_BYTES];
    
    pk_to_bytes(pk_bytes2, &pk2);
    sk_to_bytes(sk_bytes2, &sk2);
    ct_to_bytes(ct_bytes2, &ct2);
    
    TEST_ASSERT(memcmp(pk_bytes, pk_bytes2, DLPL_PK_BYTES) == 0, "PK serialization failed");
    TEST_ASSERT(memcmp(sk_bytes, sk_bytes2, DLPL_SK_BYTES) == 0, "SK serialization failed");
    TEST_ASSERT(memcmp(ct_bytes, ct_bytes2, DLPL_CT_BYTES) == 0, "CT serialization failed");
    
    TEST_PASS();
    return 1;
}

static int test_constant_time_compare(void) {
    TEST_START("Constant-time compare");
    
    uint8_t a[32] = {0x01, 0x02, 0x03};
    uint8_t b[32] = {0x01, 0x02, 0x03};
    uint8_t c[32] = {0x01, 0x02, 0x04};
    
    TEST_ASSERT(constant_time_compare(a, b, 32) == 1, "Equal arrays not detected");
    TEST_ASSERT(constant_time_compare(a, c, 32) == 0, "Different arrays not detected");
    
    TEST_PASS();
    return 1;
}

/* ==========================================================================
 * Benchmark
 * ========================================================================== */

static double get_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void run_benchmark(void) {
    printf("\n=== Benchmarks ===\n");
    printf("Parameter set: %s\n", dlpl_get_name());
    
    const int BENCH_ITER = 1000;
    double start, elapsed;
    
    public_key_t pk;
    secret_key_t sk;
    ciphertext_t ct;
    uint8_t msg[DLPL_MSG_BYTES] = {0x42};
    uint8_t msg_dec[DLPL_MSG_BYTES];
    
    /* Warm up */
    dlpl_keygen(&pk, &sk);
    dlpl_encrypt(&ct, &pk, msg);
    dlpl_decrypt(msg_dec, &ct, &sk);
    
    /* Benchmark KeyGen */
    start = get_time();
    for (int i = 0; i < BENCH_ITER; i++) {
        dlpl_keygen(&pk, &sk);
    }
    elapsed = get_time() - start;
    printf("KeyGen:  %.2f ops/sec (%.3f ms/op)\n", 
           BENCH_ITER / elapsed, elapsed * 1000 / BENCH_ITER);
    
    /* Benchmark Encrypt */
    dlpl_keygen(&pk, &sk);
    start = get_time();
    for (int i = 0; i < BENCH_ITER; i++) {
        dlpl_encrypt(&ct, &pk, msg);
    }
    elapsed = get_time() - start;
    printf("Encrypt: %.2f ops/sec (%.3f ms/op)\n", 
           BENCH_ITER / elapsed, elapsed * 1000 / BENCH_ITER);
    
    /* Benchmark Decrypt */
    dlpl_encrypt(&ct, &pk, msg);
    start = get_time();
    for (int i = 0; i < BENCH_ITER; i++) {
        dlpl_decrypt(msg_dec, &ct, &sk);
    }
    elapsed = get_time() - start;
    printf("Decrypt: %.2f ops/sec (%.3f ms/op)\n", 
           BENCH_ITER / elapsed, elapsed * 1000 / BENCH_ITER);
    
    /* Sizes */
    size_t pk_size, sk_size, ct_size;
    dlpl_get_sizes(&pk_size, &sk_size, &ct_size);
    printf("\nSizes:\n");
    printf("  Public key:  %zu bytes\n", pk_size);
    printf("  Secret key:  %zu bytes\n", sk_size);
    printf("  Ciphertext:  %zu bytes\n", ct_size);
}

/* ==========================================================================
 * Main
 * ========================================================================== */

int main(int argc, char *argv[]) {
    printf("DLPL-DH PKE Test Suite\n");
    printf("======================\n");
    printf("Parameter set: %s\n", dlpl_get_name());
    printf("n=%d, k=%d, q=%d\n\n", DLPL_N, DLPL_K, DLPL_Q);
    
    /* Initialize */
    srand((unsigned int)time(NULL));
    dlpl_random_init(NULL);
    
    /* Run tests */
    printf("=== Unit Tests ===\n");
    
    test_ntt_roundtrip();
    test_poly_mul_ntt();
    test_bc_inverse();
    test_keygen();
    test_encrypt_decrypt();
    test_encrypt_decrypt_multiple();
    test_decrypt_verify();
    test_serialization();
    test_constant_time_compare();
    
    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    if (tests_failed == 0) {
        printf("\nAll tests passed!\n");
    }
    
    /* Run benchmarks if requested */
    int run_bench = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bench") == 0 || strcmp(argv[i], "-b") == 0) {
            run_bench = 1;
        }
    }
    
    if (run_bench) {
        run_benchmark();
    } else {
        printf("\nRun with --bench for benchmarks\n");
    }
    
    return tests_failed ? 1 : 0;
}
