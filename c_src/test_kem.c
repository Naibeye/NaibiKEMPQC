/**
 * @file test_kem.c
 * @brief Test suite for DLPL-DH KEM
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dlpl_kem.h"
#include "dlpl_ntt.h"

#define NUM_TESTS 10
#define BENCH_ITERATIONS 100

static int tests_passed = 0;
static int tests_failed = 0;

static void print_result(const char *test_name, int passed) {
    if (passed) {
        printf("  %s... OK\n", test_name);
        tests_passed++;
    } else {
        printf("  %s... FAIL\n", test_name);
        tests_failed++;
    }
}

/* ==========================================================================
 * KEM Tests
 * ========================================================================== */

static int test_kem_basic(void) {
    printf("Testing basic KEM operations...\n");
    
    kem_public_key_t pk;
    kem_secret_key_t sk;
    kem_ciphertext_t ct;
    uint8_t ss_enc[DLPL_KEM_SHARED_SECRET_BYTES];
    uint8_t ss_dec[DLPL_KEM_SHARED_SECRET_BYTES];
    
    /* KeyGen */
    dlpl_kem_keygen(&pk, &sk);
    
    /* Encaps */
    dlpl_kem_encaps(&ct, ss_enc, &pk);
    
    /* Decaps */
    dlpl_kem_decaps(ss_dec, &ct, &sk);
    
    /* Compare shared secrets */
    int match = constant_time_compare(ss_enc, ss_dec, DLPL_KEM_SHARED_SECRET_BYTES);
    
    print_result("Basic encaps/decaps", match);
    return match;
}

static int test_kem_multiple(void) {
    printf("Testing multiple KEM operations...\n");
    
    kem_public_key_t pk;
    kem_secret_key_t sk;
    
    /* Generate keys once */
    dlpl_kem_keygen(&pk, &sk);
    
    int all_passed = 1;
    
    for (int i = 0; i < NUM_TESTS; i++) {
        kem_ciphertext_t ct;
        uint8_t ss_enc[DLPL_KEM_SHARED_SECRET_BYTES];
        uint8_t ss_dec[DLPL_KEM_SHARED_SECRET_BYTES];
        
        dlpl_kem_encaps(&ct, ss_enc, &pk);
        dlpl_kem_decaps(ss_dec, &ct, &sk);
        
        if (!constant_time_compare(ss_enc, ss_dec, DLPL_KEM_SHARED_SECRET_BYTES)) {
            all_passed = 0;
            break;
        }
    }
    
    print_result("Multiple encaps/decaps", all_passed);
    return all_passed;
}

static int test_kem_implicit_rejection(void) {
    printf("Testing implicit rejection...\n");
    
    kem_public_key_t pk;
    kem_secret_key_t sk;
    kem_ciphertext_t ct;
    uint8_t ss_enc[DLPL_KEM_SHARED_SECRET_BYTES];
    uint8_t ss_dec[DLPL_KEM_SHARED_SECRET_BYTES];
    uint8_t ss_bad[DLPL_KEM_SHARED_SECRET_BYTES];
    uint8_t ct_bytes[DLPL_KEM_CT_BYTES];
    uint8_t ct_bytes_bad[DLPL_KEM_CT_BYTES];
    kem_ciphertext_t ct_bad;
    
    /* KeyGen */
    dlpl_kem_keygen(&pk, &sk);
    
    /* Encaps */
    dlpl_kem_encaps(&ct, ss_enc, &pk);
    
    /* Valid decaps */
    dlpl_kem_decaps(ss_dec, &ct, &sk);
    
    /* Corrupt ciphertext */
    kem_ct_to_bytes(ct_bytes, &ct);
    memcpy(ct_bytes_bad, ct_bytes, DLPL_KEM_CT_BYTES);
    ct_bytes_bad[0] ^= 0xFF;  /* Flip first byte */
    kem_ct_from_bytes(&ct_bad, ct_bytes_bad);
    
    /* Decaps with corrupted ciphertext */
    dlpl_kem_decaps(ss_bad, &ct_bad, &sk);
    
    /* Should return different key */
    int different = !constant_time_compare(ss_enc, ss_bad, DLPL_KEM_SHARED_SECRET_BYTES);
    
    print_result("Implicit rejection (different key)", different);
    return different;
}

static int test_kem_serialization(void) {
    printf("Testing KEM serialization...\n");
    
    kem_public_key_t pk, pk2;
    kem_secret_key_t sk, sk2;
    kem_ciphertext_t ct, ct2;
    uint8_t ss_enc[DLPL_KEM_SHARED_SECRET_BYTES];
    uint8_t ss_dec[DLPL_KEM_SHARED_SECRET_BYTES];
    
    uint8_t pk_bytes[DLPL_KEM_PK_BYTES];
    uint8_t sk_bytes[DLPL_KEM_SK_BYTES];
    uint8_t ct_bytes[DLPL_KEM_CT_BYTES];
    
    /* Generate and serialize */
    dlpl_kem_keygen(&pk, &sk);
    dlpl_kem_encaps(&ct, ss_enc, &pk);
    
    kem_pk_to_bytes(pk_bytes, &pk);
    kem_sk_to_bytes(sk_bytes, &sk);
    kem_ct_to_bytes(ct_bytes, &ct);
    
    /* Deserialize */
    kem_pk_from_bytes(&pk2, pk_bytes);
    kem_sk_from_bytes(&sk2, sk_bytes);
    kem_ct_from_bytes(&ct2, ct_bytes);
    
    /* Decaps with deserialized keys */
    dlpl_kem_decaps(ss_dec, &ct2, &sk2);
    
    int match = constant_time_compare(ss_enc, ss_dec, DLPL_KEM_SHARED_SECRET_BYTES);
    
    print_result("Serialization roundtrip", match);
    return match;
}

static int test_kem_deterministic(void) {
    printf("Testing deterministic encapsulation...\n");
    
    /* Note: This tests that the same key produces consistent results,
       but each encaps uses fresh randomness */
    
    kem_public_key_t pk;
    kem_secret_key_t sk;
    
    dlpl_kem_keygen(&pk, &sk);
    
    /* Multiple encapsulations should produce different ciphertexts */
    kem_ciphertext_t ct1, ct2;
    uint8_t ss1[DLPL_KEM_SHARED_SECRET_BYTES];
    uint8_t ss2[DLPL_KEM_SHARED_SECRET_BYTES];
    uint8_t ct1_bytes[DLPL_KEM_CT_BYTES];
    uint8_t ct2_bytes[DLPL_KEM_CT_BYTES];
    
    dlpl_kem_encaps(&ct1, ss1, &pk);
    dlpl_kem_encaps(&ct2, ss2, &pk);
    
    kem_ct_to_bytes(ct1_bytes, &ct1);
    kem_ct_to_bytes(ct2_bytes, &ct2);
    
    /* Ciphertexts should be different (different random m) */
    int ct_different = !constant_time_compare(ct1_bytes, ct2_bytes, DLPL_KEM_CT_BYTES);
    
    /* But both should decaps correctly */
    uint8_t ss1_dec[DLPL_KEM_SHARED_SECRET_BYTES];
    uint8_t ss2_dec[DLPL_KEM_SHARED_SECRET_BYTES];
    
    dlpl_kem_decaps(ss1_dec, &ct1, &sk);
    dlpl_kem_decaps(ss2_dec, &ct2, &sk);
    
    int ss1_match = constant_time_compare(ss1, ss1_dec, DLPL_KEM_SHARED_SECRET_BYTES);
    int ss2_match = constant_time_compare(ss2, ss2_dec, DLPL_KEM_SHARED_SECRET_BYTES);
    
    int passed = ct_different && ss1_match && ss2_match;
    
    print_result("Different CT, correct SS", passed);
    return passed;
}

/* ==========================================================================
 * Benchmarks
 * ========================================================================== */

static void benchmark_kem(void) {
    printf("\n=== KEM Benchmarks ===\n");
    printf("Parameter set: %s\n", dlpl_kem_get_name());
    
    kem_public_key_t pk;
    kem_secret_key_t sk;
    kem_ciphertext_t ct;
    uint8_t ss[DLPL_KEM_SHARED_SECRET_BYTES];
    
    clock_t start, end;
    double keygen_time, encaps_time, decaps_time;
    
    /* Benchmark KeyGen */
    start = clock();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        dlpl_kem_keygen(&pk, &sk);
    }
    end = clock();
    keygen_time = (double)(end - start) / CLOCKS_PER_SEC * 1000 / BENCH_ITERATIONS;
    
    /* Benchmark Encaps */
    start = clock();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        dlpl_kem_encaps(&ct, ss, &pk);
    }
    end = clock();
    encaps_time = (double)(end - start) / CLOCKS_PER_SEC * 1000 / BENCH_ITERATIONS;
    
    /* Benchmark Decaps */
    dlpl_kem_encaps(&ct, ss, &pk);  /* Generate valid ciphertext */
    start = clock();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        dlpl_kem_decaps(ss, &ct, &sk);
    }
    end = clock();
    decaps_time = (double)(end - start) / CLOCKS_PER_SEC * 1000 / BENCH_ITERATIONS;
    
    printf("KeyGen:  %.3f ms (%.1f ops/sec)\n", keygen_time, 1000.0/keygen_time);
    printf("Encaps:  %.3f ms (%.1f ops/sec)\n", encaps_time, 1000.0/encaps_time);
    printf("Decaps:  %.3f ms (%.1f ops/sec)\n", decaps_time, 1000.0/decaps_time);
    
    /* Print sizes */
    size_t pk_size, sk_size, ct_size, ss_size;
    dlpl_kem_get_sizes(&pk_size, &sk_size, &ct_size, &ss_size);
    
    printf("\nSizes:\n");
    printf("  Public key:     %zu bytes\n", pk_size);
    printf("  Secret key:     %zu bytes\n", sk_size);
    printf("  Ciphertext:     %zu bytes\n", ct_size);
    printf("  Shared secret:  %zu bytes\n", ss_size);
}

/* ==========================================================================
 * Main
 * ========================================================================== */

int main(int argc, char *argv[]) {
    int run_bench = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bench") == 0) {
            run_bench = 1;
        }
    }
    
    printf("DLPL-DH KEM Test Suite\n");
    printf("======================\n");
    printf("Parameter set: %s\n", dlpl_kem_get_name());
    printf("n=%d, k=%d, q=%d\n\n", DLPL_N, DLPL_K, DLPL_Q);
    
    /* Initialize */
    srand((unsigned int)time(NULL));
    dlpl_random_init(NULL);
    ntt_init();
    
    printf("=== Unit Tests ===\n");
    
    test_kem_basic();
    test_kem_multiple();
    test_kem_implicit_rejection();
    test_kem_serialization();
    test_kem_deterministic();
    
    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    if (tests_failed == 0) {
        printf("\nAll tests passed!\n");
    }
    
    if (run_bench) {
        benchmark_kem();
    } else {
        printf("\nRun with --bench for benchmarks\n");
    }
    
    return tests_failed > 0 ? 1 : 0;
}
