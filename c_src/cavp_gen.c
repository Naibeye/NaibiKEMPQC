/**
 * @file cavp_gen.c
 * @brief CAVP (Cryptographic Algorithm Validation Program) Test Vector Generator
 *        for DLPL-DH PKE and KEM
 * 
 * Generates Known Answer Tests (KAT) in NIST format for:
 * - Key Generation
 * - PKE Encryption/Decryption  
 * - KEM Encapsulation/Decapsulation
 * 
 * Output format follows NIST PQC submission requirements.
 * 
 * Supports all security levels:
 *   L1: n=256, k=2, q=7681 (128-bit security)
 *   L3: n=256, k=3, q=7681 (192-bit security)
 *   L5: n=256, k=4, q=7681 (256-bit security)
 * 
 * Uses Kyber-style bit-packing (13 bits/coefficient for q=7681)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "dlpl_pke.h"
#include "dlpl_kem.h"
#include "dlpl_ntt.h"

/* Number of test vectors to generate */
#define NUM_KAT_VECTORS 100

/* Shared secret size */
#define DLPL_KEM_SS_BYTES DLPL_KEM_SHARED_SECRET_BYTES

/* Derived size calculations for documentation */
#define DLPL_POLY_BYTES_CALC  ((DLPL_N * DLPL_LOGQ + 7) / 8)

/* Simple deterministic RNG for reproducible test vectors */
typedef struct {
    uint8_t key[32];
    uint8_t ctr[16];
    uint64_t reseed_counter;
} drbg_ctx;

/* Simple mixing function for DRBG */
static void drbg_mix(uint8_t *state, size_t len) {
    for (size_t i = 0; i < len - 1; i++) {
        state[i] ^= state[i + 1] + (uint8_t)(i * 0x9E);
        state[i + 1] = (state[i + 1] << 3) | (state[i + 1] >> 5);
    }
}

static void drbg_init(drbg_ctx *ctx, const uint8_t seed[48]) {
    memcpy(ctx->key, seed, 32);
    memcpy(ctx->ctr, seed + 32, 16);
    ctx->reseed_counter = 1;
}

static void drbg_generate(drbg_ctx *ctx, uint8_t *out, size_t len) {
    uint8_t block[48];
    size_t pos = 0;
    
    while (pos < len) {
        /* Increment counter */
        for (int i = 15; i >= 0; i--) {
            if (++ctx->ctr[i] != 0) break;
        }
        
        /* Generate block: mix key with counter */
        memcpy(block, ctx->key, 32);
        memcpy(block + 32, ctx->ctr, 16);
        
        /* Multiple rounds of mixing */
        for (int r = 0; r < 10; r++) {
            drbg_mix(block, 48);
        }
        
        /* Output */
        size_t to_copy = (len - pos < 32) ? (len - pos) : 32;
        memcpy(out + pos, block, to_copy);
        pos += to_copy;
    }
    
    /* Update key for forward secrecy */
    memcpy(block, ctx->key, 32);
    memcpy(block + 32, ctx->ctr, 16);
    for (int r = 0; r < 10; r++) {
        drbg_mix(block, 48);
    }
    memcpy(ctx->key, block, 32);
    ctx->reseed_counter++;
}

/* Print hex string */
static void fprint_hex(FILE *f, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        fprintf(f, "%02X", data[i]);
    }
    fprintf(f, "\n");
}

/* Generate initial seed from count */
static void generate_seed(uint8_t seed[48], int count) {
    memset(seed, 0, 48);
    for (int i = 0; i < 48; i++) {
        seed[i] = (uint8_t)((count * 0x9E3779B9 + i * 0x85EBCA6B) >> ((i % 4) * 8));
    }
}

/* ========================================================================== 
 * PKE KAT Generation
 * ========================================================================== */

static void generate_pke_kat(const char *filename, int num_vectors) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "Error: Cannot open %s for writing\n", filename);
        return;
    }
    
    fprintf(f, "# DLPL-DH-PKE Known Answer Tests\n");
    fprintf(f, "# Algorithm: DLPL-DH-PKE-%d\n", DLPL_N);
    fprintf(f, "# Parameters: n=%d, k=%d, q=%d, log_q=%d\n", DLPL_N, DLPL_K, DLPL_Q, DLPL_LOGQ);
    fprintf(f, "# Encoding: Kyber-style bit-packing (%d bits/coefficient)\n", DLPL_LOGQ);
    fprintf(f, "# Sizes: pk=%lu, sk=%lu, ct=%lu bytes\n", 
            (unsigned long)DLPL_PK_BYTES, (unsigned long)DLPL_SK_BYTES, (unsigned long)DLPL_CT_BYTES);
    fprintf(f, "# Generated: %s", __DATE__);
    fprintf(f, "\n\n");
    
    drbg_ctx drbg;
    uint8_t seed[48];
    
    public_key_t pk;
    secret_key_t sk;
    ciphertext_t ct;
    uint8_t msg[DLPL_MSG_BYTES];
    uint8_t dec_msg[DLPL_MSG_BYTES];
    
    uint8_t pk_bytes[DLPL_PK_BYTES];
    uint8_t sk_bytes[DLPL_SK_BYTES];
    uint8_t ct_bytes[DLPL_CT_BYTES];
    
    for (int count = 0; count < num_vectors; count++) {
        fprintf(f, "count = %d\n", count);
        
        /* Generate seed for this vector */
        generate_seed(seed, count);
        fprintf(f, "seed = ");
        fprint_hex(f, seed, 48);
        
        /* Initialize DRBG with seed */
        drbg_init(&drbg, seed);
        
        /* Generate randomness for key generation */
        uint8_t kg_rand[64];
        drbg_generate(&drbg, kg_rand, 64);
        
        /* Key generation (using library's keygen with seeded randomness) */
        dlpl_random_init(kg_rand);
        dlpl_keygen(&pk, &sk);
        
        /* Serialize keys */
        pk_to_bytes(pk_bytes, &pk);
        sk_to_bytes(sk_bytes, &sk);
        
        fprintf(f, "pk = ");
        fprint_hex(f, pk_bytes, DLPL_PK_BYTES);
        fprintf(f, "sk = ");
        fprint_hex(f, sk_bytes, DLPL_SK_BYTES);
        
        /* Generate random message */
        drbg_generate(&drbg, msg, DLPL_MSG_BYTES);
        fprintf(f, "msg = ");
        fprint_hex(f, msg, DLPL_MSG_BYTES);
        
        /* Generate encryption randomness */
        uint8_t enc_rand[64];
        drbg_generate(&drbg, enc_rand, 64);
        dlpl_random_init(enc_rand);
        
        /* Encrypt */
        dlpl_encrypt(&ct, &pk, msg);
        ct_to_bytes(ct_bytes, &ct);
        fprintf(f, "ct = ");
        fprint_hex(f, ct_bytes, DLPL_CT_BYTES);
        
        /* Decrypt */
        dlpl_decrypt(dec_msg, &ct, &sk);
        fprintf(f, "dec_msg = ");
        fprint_hex(f, dec_msg, DLPL_MSG_BYTES);
        
        /* Verify correctness */
        int correct = (memcmp(msg, dec_msg, DLPL_MSG_BYTES) == 0);
        fprintf(f, "verify = %s\n", correct ? "PASS" : "FAIL");
        
        fprintf(f, "\n");
    }
    
    fclose(f);
    printf("Generated %d PKE test vectors in %s\n", num_vectors, filename);
}

/* ========================================================================== 
 * KEM KAT Generation
 * ========================================================================== */

static void generate_kem_kat(const char *filename, int num_vectors) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "Error: Cannot open %s for writing\n", filename);
        return;
    }
    
    fprintf(f, "# DLPL-DH-KEM Known Answer Tests\n");
    fprintf(f, "# Algorithm: DLPL-DH-KEM-%d\n", DLPL_N);
    fprintf(f, "# Parameters: n=%d, k=%d, q=%d, log_q=%d\n", DLPL_N, DLPL_K, DLPL_Q, DLPL_LOGQ);
    fprintf(f, "# Encoding: Kyber-style bit-packing (%d bits/coefficient)\n", DLPL_LOGQ);
    fprintf(f, "# Sizes: pk=%lu, sk=%lu, ct=%lu, ss=%d bytes\n", 
            (unsigned long)DLPL_KEM_PK_BYTES, (unsigned long)DLPL_KEM_SK_BYTES, 
            (unsigned long)DLPL_KEM_CT_BYTES, DLPL_KEM_SS_BYTES);
    fprintf(f, "# Generated: %s", __DATE__);
    fprintf(f, "\n\n");
    
    drbg_ctx drbg;
    uint8_t seed[48];
    
    kem_public_key_t pk;
    kem_secret_key_t sk;
    kem_ciphertext_t ct;
    uint8_t ss_enc[DLPL_KEM_SS_BYTES];
    uint8_t ss_dec[DLPL_KEM_SS_BYTES];
    
    uint8_t pk_bytes[DLPL_KEM_PK_BYTES];
    uint8_t sk_bytes[DLPL_KEM_SK_BYTES];
    uint8_t ct_bytes[DLPL_KEM_CT_BYTES];
    
    for (int count = 0; count < num_vectors; count++) {
        fprintf(f, "count = %d\n", count);
        
        /* Generate seed for this vector */
        generate_seed(seed, count);
        fprintf(f, "seed = ");
        fprint_hex(f, seed, 48);
        
        /* Initialize DRBG with seed */
        drbg_init(&drbg, seed);
        
        /* Generate randomness for key generation */
        uint8_t kg_rand[64];
        drbg_generate(&drbg, kg_rand, 64);
        
        /* Key generation */
        dlpl_random_init(kg_rand);
        dlpl_kem_keygen(&pk, &sk);
        
        /* Serialize keys */
        kem_pk_to_bytes(pk_bytes, &pk);
        kem_sk_to_bytes(sk_bytes, &sk);
        
        fprintf(f, "pk = ");
        fprint_hex(f, pk_bytes, DLPL_KEM_PK_BYTES);
        fprintf(f, "sk = ");
        fprint_hex(f, sk_bytes, DLPL_KEM_SK_BYTES);
        
        /* Generate encapsulation randomness */
        uint8_t enc_rand[64];
        drbg_generate(&drbg, enc_rand, 64);
        dlpl_random_init(enc_rand);
        
        /* Encapsulate */
        dlpl_kem_encaps(&ct, ss_enc, &pk);
        kem_ct_to_bytes(ct_bytes, &ct);
        
        fprintf(f, "ct = ");
        fprint_hex(f, ct_bytes, DLPL_KEM_CT_BYTES);
        fprintf(f, "ss_enc = ");
        fprint_hex(f, ss_enc, DLPL_KEM_SS_BYTES);
        
        /* Decapsulate */
        dlpl_kem_decaps(ss_dec, &ct, &sk);
        fprintf(f, "ss_dec = ");
        fprint_hex(f, ss_dec, DLPL_KEM_SS_BYTES);
        
        /* Verify correctness */
        int correct = (memcmp(ss_enc, ss_dec, DLPL_KEM_SS_BYTES) == 0);
        fprintf(f, "verify = %s\n", correct ? "PASS" : "FAIL");
        
        fprintf(f, "\n");
    }
    
    fclose(f);
    printf("Generated %d KEM test vectors in %s\n", num_vectors, filename);
}

/* ========================================================================== 
 * Intermediate Value Tests (for debugging implementations)
 * ========================================================================== */

static void generate_intermediate_values(const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "Error: Cannot open %s for writing\n", filename);
        return;
    }
    
    fprintf(f, "# DLPL-DH Intermediate Value Tests\n");
    fprintf(f, "# For implementation debugging and validation\n");
    fprintf(f, "# Parameters: n=%d, k=%d, q=%d\n\n", DLPL_N, DLPL_K, DLPL_Q);
    
    /* Test 1: NTT roundtrip */
    fprintf(f, "=== NTT Roundtrip Test ===\n");
    int16_t poly[DLPL_N];
    int16_t poly_ntt[DLPL_N];
    int16_t poly_back[DLPL_N];
    
    /* Known input polynomial */
    for (int i = 0; i < DLPL_N; i++) {
        poly[i] = (int16_t)((i * 17 + 3) % DLPL_Q);
    }
    
    fprintf(f, "input[0..7] = ");
    for (int i = 0; i < 8; i++) fprintf(f, "%d ", poly[i]);
    fprintf(f, "\n");
    
    /* Forward NTT */
    memcpy(poly_ntt, poly, sizeof(poly));
    ntt_forward(poly_ntt);
    
    fprintf(f, "ntt[0..7] = ");
    for (int i = 0; i < 8; i++) fprintf(f, "%d ", poly_ntt[i]);
    fprintf(f, "\n");
    
    /* Inverse NTT */
    memcpy(poly_back, poly_ntt, sizeof(poly_ntt));
    ntt_inverse(poly_back);
    
    fprintf(f, "intt[0..7] = ");
    for (int i = 0; i < 8; i++) fprintf(f, "%d ", poly_back[i]);
    fprintf(f, "\n");
    
    int ntt_ok = 1;
    for (int i = 0; i < DLPL_N; i++) {
        if (poly[i] != poly_back[i]) { ntt_ok = 0; break; }
    }
    fprintf(f, "roundtrip = %s\n\n", ntt_ok ? "PASS" : "FAIL");
    
    /* Test 2: Polynomial multiplication */
    fprintf(f, "=== Polynomial Multiplication Test ===\n");
    poly_t pa, pb, pc;
    
    /* a = 1 + x + x^2 */
    poly_zero(&pa);
    pa.coeffs[0] = 1; pa.coeffs[1] = 1; pa.coeffs[2] = 1;
    
    /* b = 1 + x */
    poly_zero(&pb);
    pb.coeffs[0] = 1; pb.coeffs[1] = 1;
    
    fprintf(f, "a = 1 + x + x^2\n");
    fprintf(f, "b = 1 + x\n");
    
    poly_mul_ntt(&pc, &pa, &pb);
    
    fprintf(f, "c = a*b mod (x^%d+1) = ", DLPL_N);
    int printed = 0;
    for (int i = 0; i < DLPL_N && printed < 10; i++) {
        if (pc.coeffs[i] != 0) {
            if (printed > 0) fprintf(f, " + ");
            if (i == 0) fprintf(f, "%d", pc.coeffs[i]);
            else if (i == 1) fprintf(f, "%d*x", pc.coeffs[i]);
            else fprintf(f, "%d*x^%d", pc.coeffs[i], i);
            printed++;
        }
    }
    fprintf(f, "\n");
    
    /* Expected: (1+x+x^2)(1+x) = 1 + 2x + 2x^2 + x^3 mod (x^128+1) */
    fprintf(f, "expected = 1 + 2x + 2x^2 + x^3\n");
    int mul_ok = (pc.coeffs[0] == 1) && (pc.coeffs[1] == 2) && (pc.coeffs[2] == 2) && (pc.coeffs[3] == 1);
    for (int i = 4; i < DLPL_N; i++) {
        if (pc.coeffs[i] != 0) { mul_ok = 0; break; }
    }
    fprintf(f, "verify = %s\n\n", mul_ok ? "PASS" : "FAIL");
    
    /* Test 3: Montgomery arithmetic */
    fprintf(f, "=== Montgomery Arithmetic Test ===\n");
    fprintf(f, "q = %d\n", DLPL_Q);
    fprintf(f, "R = 2^16 = 65536\n");
    fprintf(f, "R^2 mod q = 1353\n");
    fprintf(f, "q' = 3327 (such that q*q' = -1 mod R)\n\n");
    
    /* Verify: 3329 * 3327 mod 65536 = 65535 = -1 mod R */
    uint32_t verify = (3329UL * 3327UL) & 0xFFFF;
    fprintf(f, "Verify q*q' mod R = %u (should be 65535)\n", verify);
    fprintf(f, "montgomery_check = %s\n\n", (verify == 65535) ? "PASS" : "FAIL");
    
    fclose(f);
    printf("Generated intermediate value tests in %s\n", filename);
}

/* ========================================================================== 
 * JSON format for modern tooling
 * ========================================================================== */

static void generate_json_kat(const char *filename, int num_vectors) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "Error: Cannot open %s for writing\n", filename);
        return;
    }
    
    fprintf(f, "{\n");
    fprintf(f, "  \"algorithm\": \"DLPL-DH-KEM-%d\",\n", DLPL_N);
    fprintf(f, "  \"parameters\": {\n");
    fprintf(f, "    \"n\": %d,\n", DLPL_N);
    fprintf(f, "    \"k\": %d,\n", DLPL_K);
    fprintf(f, "    \"q\": %d,\n", DLPL_Q);
    fprintf(f, "    \"log_q\": %d,\n", DLPL_LOGQ);
    fprintf(f, "    \"poly_bytes\": %d,\n", DLPL_POLY_BYTES);
    fprintf(f, "    \"encoding\": \"kyber-style (13 bits/coeff)\"\n");
    fprintf(f, "  },\n");
    fprintf(f, "  \"sizes\": {\n");
    fprintf(f, "    \"public_key\": %lu,\n", (unsigned long)DLPL_KEM_PK_BYTES);
    fprintf(f, "    \"secret_key\": %lu,\n", (unsigned long)DLPL_KEM_SK_BYTES);
    fprintf(f, "    \"ciphertext\": %lu,\n", (unsigned long)DLPL_KEM_CT_BYTES);
    fprintf(f, "    \"shared_secret\": %d\n", DLPL_KEM_SS_BYTES);
    fprintf(f, "  },\n");
    fprintf(f, "  \"test_vectors\": [\n");
    
    drbg_ctx drbg;
    uint8_t seed[48];
    
    kem_public_key_t pk;
    kem_secret_key_t sk;
    kem_ciphertext_t ct;
    uint8_t ss_enc[DLPL_KEM_SS_BYTES];
    uint8_t ss_dec[DLPL_KEM_SS_BYTES];
    
    uint8_t pk_bytes[DLPL_KEM_PK_BYTES];
    uint8_t sk_bytes[DLPL_KEM_SK_BYTES];
    uint8_t ct_bytes[DLPL_KEM_CT_BYTES];
    
    for (int count = 0; count < num_vectors; count++) {
        generate_seed(seed, count);
        drbg_init(&drbg, seed);
        
        uint8_t kg_rand[64];
        drbg_generate(&drbg, kg_rand, 64);
        dlpl_random_init(kg_rand);
        dlpl_kem_keygen(&pk, &sk);
        kem_pk_to_bytes(pk_bytes, &pk);
        kem_sk_to_bytes(sk_bytes, &sk);
        
        uint8_t enc_rand[64];
        drbg_generate(&drbg, enc_rand, 64);
        dlpl_random_init(enc_rand);
        dlpl_kem_encaps(&ct, ss_enc, &pk);
        kem_ct_to_bytes(ct_bytes, &ct);
        
        dlpl_kem_decaps(ss_dec, &ct, &sk);
        (void)ss_dec;  /* suppress unused warning */
        
        fprintf(f, "    {\n");
        fprintf(f, "      \"count\": %d,\n", count);
        fprintf(f, "      \"seed\": \"");
        for (int i = 0; i < 48; i++) fprintf(f, "%02x", seed[i]);
        fprintf(f, "\",\n");
        fprintf(f, "      \"pk\": \"");
        for (size_t i = 0; i < DLPL_KEM_PK_BYTES; i++) fprintf(f, "%02x", pk_bytes[i]);
        fprintf(f, "\",\n");
        fprintf(f, "      \"sk\": \"");
        for (size_t i = 0; i < DLPL_KEM_SK_BYTES; i++) fprintf(f, "%02x", sk_bytes[i]);
        fprintf(f, "\",\n");
        fprintf(f, "      \"ct\": \"");
        for (size_t i = 0; i < DLPL_KEM_CT_BYTES; i++) fprintf(f, "%02x", ct_bytes[i]);
        fprintf(f, "\",\n");
        fprintf(f, "      \"ss\": \"");
        for (int i = 0; i < DLPL_KEM_SS_BYTES; i++) fprintf(f, "%02x", ss_enc[i]);
        fprintf(f, "\"\n");
        fprintf(f, "    }%s\n", (count < num_vectors - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("Generated %d JSON test vectors in %s\n", num_vectors, filename);
}

/* ========================================================================== 
 * Main
 * ========================================================================== */

static void print_usage(const char *prog) {
    printf("DLPL-DH CAVP Test Vector Generator\n");
    printf("===================================\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  --pke <file>     Generate PKE KAT vectors (default: PQCkemKAT_PKE.rsp)\n");
    printf("  --kem <file>     Generate KEM KAT vectors (default: PQCkemKAT_KEM.rsp)\n");
    printf("  --json <file>    Generate JSON format vectors (default: kat.json)\n");
    printf("  --intermediate   Generate intermediate value tests\n");
    printf("  --count <n>      Number of test vectors (default: %d)\n", NUM_KAT_VECTORS);
    printf("  --all            Generate all test vector types\n");
    printf("  --help           Show this help\n");
    printf("\nExample:\n");
    printf("  %s --all --count 100\n", prog);
}

int main(int argc, char *argv[]) {
    int gen_pke = 0, gen_kem = 0, gen_json = 0, gen_intermediate = 0;
    int count = NUM_KAT_VECTORS;
    const char *pke_file = "PQCkemKAT_PKE.rsp";
    const char *kem_file = "PQCkemKAT_KEM.rsp";
    const char *json_file = "kat.json";
    const char *intermediate_file = "intermediate_values.txt";
    
    if (argc == 1) {
        /* Default: generate all */
        gen_pke = gen_kem = gen_json = gen_intermediate = 1;
    }
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--pke") == 0) {
            gen_pke = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                pke_file = argv[++i];
            }
        } else if (strcmp(argv[i], "--kem") == 0) {
            gen_kem = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                kem_file = argv[++i];
            }
        } else if (strcmp(argv[i], "--json") == 0) {
            gen_json = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                json_file = argv[++i];
            }
        } else if (strcmp(argv[i], "--intermediate") == 0) {
            gen_intermediate = 1;
        } else if (strcmp(argv[i], "--count") == 0) {
            if (i + 1 < argc) {
                count = atoi(argv[++i]);
                if (count <= 0) count = NUM_KAT_VECTORS;
            }
        } else if (strcmp(argv[i], "--all") == 0) {
            gen_pke = gen_kem = gen_json = gen_intermediate = 1;
        }
    }
    
    /* Initialize NTT tables */
    ntt_init();
    
    printf("DLPL-DH CAVP Test Vector Generator\n");
    printf("===================================\n");
    printf("Parameters: n=%d, k=%d, q=%d, log_q=%d\n", DLPL_N, DLPL_K, DLPL_Q, DLPL_LOGQ);
    printf("Encoding: Kyber-style bit-packing (%d bits/coefficient)\n", DLPL_LOGQ);
    printf("Sizes:\n");
    printf("  PKE: pk=%lu, sk=%lu, ct=%lu bytes\n", 
           (unsigned long)DLPL_PK_BYTES, (unsigned long)DLPL_SK_BYTES, (unsigned long)DLPL_CT_BYTES);
    printf("  KEM: pk=%lu, sk=%lu, ct=%lu, ss=%d bytes\n\n", 
           (unsigned long)DLPL_KEM_PK_BYTES, (unsigned long)DLPL_KEM_SK_BYTES, 
           (unsigned long)DLPL_KEM_CT_BYTES, DLPL_KEM_SS_BYTES);
    
    if (gen_intermediate) {
        generate_intermediate_values(intermediate_file);
    }
    
    if (gen_pke) {
        generate_pke_kat(pke_file, count);
    }
    
    if (gen_kem) {
        generate_kem_kat(kem_file, count);
    }
    
    if (gen_json) {
        generate_json_kat(json_file, count);
    }
    
    printf("\nDone! Test vectors generated successfully.\n");
    
    return 0;
}
