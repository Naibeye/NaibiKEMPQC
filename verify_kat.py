#!/usr/bin/env python3
"""
Verify CAVP/KAT test vectors for DLPL-DH KEM

This script reads the generated KAT files and verifies:
1. PKE encrypt/decrypt consistency
2. KEM encaps/decaps consistency
3. JSON format parsing

Supports all security levels: L1 (k=2), L3 (k=3), L5 (k=4)
"""

import os
import json
import hashlib
from pathlib import Path

# Parameters matching C implementation with Kyber-style bit-packing
# q = 7681, n = 256, LOGQ = 13 bits
# poly_bytes = (n * LOGQ + 7) // 8 = (256 * 13 + 7) // 8 = 416 bytes

N = 256
Q = 7681
LOGQ = 13
POLY_BYTES = (N * LOGQ + 7) // 8  # 416 bytes per polynomial

# Security level configurations
LEVELS = {
    'L1': {'k': 2, 'name': 'DLPL-256'},
    'L3': {'k': 3, 'name': 'DLPL-384'},
    'L5': {'k': 4, 'name': 'DLPL-1024'},
}

def get_sizes(k):
    """Calculate key/ciphertext sizes for given k parameter"""
    # PKE sizes
    pk_bytes = 2 * k * k * POLY_BYTES      # A and t matrices: 2 * k² * poly_bytes
    sk_pke_bytes = 2 * k * POLY_BYTES      # s and e vectors: 2 * k * poly_bytes
    ct_bytes = k * k * POLY_BYTES + 32     # u matrix + v hash: k² * poly_bytes + 32
    
    # KEM sizes (includes pk, z, and h(pk) in secret key)
    sk_kem_bytes = sk_pke_bytes + pk_bytes + 64  # sk_pke + pk + z(32) + h_pk(32)
    ss_bytes = 32
    
    return {
        'pk': pk_bytes,
        'sk_pke': sk_pke_bytes,
        'sk_kem': sk_kem_bytes,
        'ct': ct_bytes,
        'ss': ss_bytes,
    }

# Default to L1 for backwards compatibility
K = 2
sizes = get_sizes(K)
PK_BYTES = sizes['pk']
SK_BYTES = sizes['sk_pke']
CT_BYTES = sizes['ct']
KEM_PK_BYTES = sizes['pk']
KEM_SK_BYTES = sizes['sk_kem']
KEM_CT_BYTES = sizes['ct']
KEM_SS_BYTES = sizes['ss']


def parse_kem_kat(filename):
    """Parse KEM KAT response file"""
    vectors = []
    current = {}
    
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('count = '):
                if current:
                    vectors.append(current)
                current = {'count': int(line.split('=')[1].strip())}
            elif '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                current[key] = value
        
        if current:
            vectors.append(current)
    
    return vectors


def parse_pke_kat(filename):
    """Parse PKE KAT response file"""
    return parse_kem_kat(filename)  # Same format


def detect_security_level(pk_len):
    """Detect security level from public key size"""
    for level, config in LEVELS.items():
        sizes = get_sizes(config['k'])
        if sizes['pk'] == pk_len:
            return level, config['k']
    return None, None


def verify_kem_vectors(vectors):
    """Verify KEM test vectors"""
    print(f"\nVerifying {len(vectors)} KEM test vectors...")
    
    passed = 0
    failed = 0
    detected_level = None
    
    for v in vectors:
        count = v.get('count', '?')
        
        # Check required fields
        required = ['seed', 'pk', 'sk', 'ct', 'ss_enc', 'ss_dec', 'verify']
        missing = [f for f in required if f not in v]
        if missing:
            print(f"  Vector {count}: SKIP - missing fields: {missing}")
            continue
        
        # Check sizes
        pk_hex = v['pk']
        sk_hex = v['sk']
        ct_hex = v['ct']
        ss_enc_hex = v['ss_enc']
        ss_dec_hex = v['ss_dec']
        
        pk_len = len(pk_hex) // 2
        sk_len = len(sk_hex) // 2
        ct_len = len(ct_hex) // 2
        ss_enc_len = len(ss_enc_hex) // 2
        ss_dec_len = len(ss_dec_hex) // 2
        
        # Detect security level from pk size
        if detected_level is None:
            level, k = detect_security_level(pk_len)
            if level:
                detected_level = level
                sizes = get_sizes(k)
                print(f"  Detected security level: {level} (k={k})")
                print(f"  Expected sizes: PK={sizes['pk']}, SK(KEM)={sizes['sk_kem']}, CT={sizes['ct']}")
        
        # Get expected sizes for detected level
        if detected_level:
            k = LEVELS[detected_level]['k']
            sizes = get_sizes(k)
            exp_pk = sizes['pk']
            exp_sk = sizes['sk_kem']
            exp_ct = sizes['ct']
            exp_ss = sizes['ss']
        else:
            # Fallback to defaults
            exp_pk = KEM_PK_BYTES
            exp_sk = KEM_SK_BYTES
            exp_ct = KEM_CT_BYTES
            exp_ss = KEM_SS_BYTES
        
        # Verify sizes match expected
        size_ok = True
        if pk_len != exp_pk:
            print(f"  Vector {count}: pk size {pk_len} != expected {exp_pk}")
            size_ok = False
        if sk_len != exp_sk:
            print(f"  Vector {count}: sk size {sk_len} != expected {exp_sk}")
            size_ok = False
        if ct_len != exp_ct:
            print(f"  Vector {count}: ct size {ct_len} != expected {exp_ct}")
            size_ok = False
        if ss_enc_len != exp_ss:
            print(f"  Vector {count}: ss_enc size {ss_enc_len} != expected {exp_ss}")
            size_ok = False
        if ss_dec_len != exp_ss:
            print(f"  Vector {count}: ss_dec size {ss_dec_len} != expected {exp_ss}")
            size_ok = False
        
        # Verify shared secrets match
        ss_match = (ss_enc_hex.lower() == ss_dec_hex.lower())
        verify_field = v['verify']
        
        if ss_match and verify_field == 'PASS' and size_ok:
            passed += 1
        else:
            failed += 1
            print(f"  Vector {count}: FAIL")
            if not ss_match:
                print(f"    ss_enc != ss_dec")
            if verify_field != 'PASS':
                print(f"    verify = {verify_field}")
    
    print(f"\nKEM Results: {passed} passed, {failed} failed")
    return failed == 0


def verify_pke_vectors(vectors):
    """Verify PKE test vectors"""
    print(f"\nVerifying {len(vectors)} PKE test vectors...")
    
    passed = 0
    failed = 0
    detected_level = None
    
    for v in vectors:
        count = v.get('count', '?')
        
        # Check required fields
        required = ['seed', 'pk', 'sk', 'msg', 'ct', 'dec_msg', 'verify']
        missing = [f for f in required if f not in v]
        if missing:
            print(f"  Vector {count}: SKIP - missing fields: {missing}")
            continue
        
        # Verify message matches
        msg_hex = v['msg']
        dec_msg_hex = v['dec_msg']
        msg_match = (msg_hex.lower() == dec_msg_hex.lower())
        verify_field = v['verify']
        
        # Check sizes
        pk_len = len(v['pk']) // 2
        sk_len = len(v['sk']) // 2
        ct_len = len(v['ct']) // 2
        
        # Detect security level from pk size
        if detected_level is None:
            level, k = detect_security_level(pk_len)
            if level:
                detected_level = level
                sizes = get_sizes(k)
                print(f"  Detected security level: {level} (k={k})")
                print(f"  Expected sizes: PK={sizes['pk']}, SK(PKE)={sizes['sk_pke']}, CT={sizes['ct']}")
        
        # Get expected sizes for detected level
        if detected_level:
            k = LEVELS[detected_level]['k']
            sizes = get_sizes(k)
            exp_pk = sizes['pk']
            exp_sk = sizes['sk_pke']
            exp_ct = sizes['ct']
        else:
            # Fallback to defaults
            exp_pk = PK_BYTES
            exp_sk = SK_BYTES
            exp_ct = CT_BYTES
        
        size_ok = True
        if pk_len != exp_pk:
            print(f"  Vector {count}: pk size {pk_len} != expected {exp_pk}")
            size_ok = False
        if sk_len != exp_sk:
            print(f"  Vector {count}: sk size {sk_len} != expected {exp_sk}")
            size_ok = False
        if ct_len != exp_ct:
            print(f"  Vector {count}: ct size {ct_len} != expected {exp_ct}")
            size_ok = False
        
        if msg_match and verify_field == 'PASS' and size_ok:
            passed += 1
        else:
            failed += 1
            print(f"  Vector {count}: FAIL")
            if not msg_match:
                print(f"    msg != dec_msg")
            if verify_field != 'PASS':
                print(f"    verify = {verify_field}")
    
    print(f"\nPKE Results: {passed} passed, {failed} failed")
    return failed == 0


def verify_json_kat(filename):
    """Verify JSON format KAT file"""
    print(f"\nVerifying JSON KAT file: {filename}")
    
    with open(filename, 'r') as f:
        data = json.load(f)
    
    print(f"  Algorithm: {data.get('algorithm', 'N/A')}")
    print(f"  Parameters: {data.get('parameters', {})}")
    print(f"  Sizes: {data.get('sizes', {})}")
    
    vectors = data.get('test_vectors', [])
    print(f"  Test vectors: {len(vectors)}")
    
    # Verify each vector has required fields
    passed = 0
    for v in vectors:
        required = ['count', 'seed', 'pk', 'sk', 'ct', 'ss']
        if all(f in v for f in required):
            passed += 1
    
    print(f"  Valid vectors: {passed}/{len(vectors)}")
    return passed == len(vectors)


def verify_intermediate_values(filename):
    """Verify intermediate value tests"""
    print(f"\nVerifying intermediate values: {filename}")
    
    with open(filename, 'r') as f:
        content = f.read()
    
    # Check for PASS markers
    ntt_pass = 'roundtrip = PASS' in content
    mul_pass = 'verify = PASS' in content  
    mont_pass = 'montgomery_check = PASS' in content
    
    print(f"  NTT roundtrip: {'PASS' if ntt_pass else 'FAIL'}")
    print(f"  Polynomial mul: {'PASS' if mul_pass else 'FAIL'}")
    print(f"  Montgomery check: {'PASS' if mont_pass else 'FAIL'}")
    
    return ntt_pass and mul_pass and mont_pass


def main():
    base_dir = Path(__file__).parent / 'c_src'
    
    print("=" * 60)
    print("DLPL-DH KAT Verification")
    print("=" * 60)
    
    # Print expected sizes for all levels
    print("\nExpected sizes (Kyber-style 13-bit encoding):")
    print(f"  poly_bytes = {POLY_BYTES} bytes (n={N}, LOGQ={LOGQ})")
    print()
    for level, config in LEVELS.items():
        k = config['k']
        sizes = get_sizes(k)
        print(f"  {level} (k={k}): PK={sizes['pk']}B, SK_PKE={sizes['sk_pke']}B, "
              f"SK_KEM={sizes['sk_kem']}B, CT={sizes['ct']}B")
    print()
    
    all_passed = True
    
    # Verify KEM KAT
    kem_kat = base_dir / 'PQCkemKAT_KEM.rsp'
    if kem_kat.exists():
        vectors = parse_kem_kat(kem_kat)
        if not verify_kem_vectors(vectors):
            all_passed = False
    else:
        print(f"\nKEM KAT file not found: {kem_kat}")
        all_passed = False
    
    # Verify PKE KAT
    pke_kat = base_dir / 'PQCkemKAT_PKE.rsp'
    if pke_kat.exists():
        vectors = parse_pke_kat(pke_kat)
        if not verify_pke_vectors(vectors):
            all_passed = False
    else:
        print(f"\nPKE KAT file not found: {pke_kat}")
        all_passed = False
    
    # Verify JSON KAT
    json_kat = base_dir / 'kat.json'
    if json_kat.exists():
        if not verify_json_kat(json_kat):
            all_passed = False
    else:
        print(f"\nJSON KAT file not found: {json_kat}")
    
    # Verify intermediate values
    intermediate = base_dir / 'intermediate_values.txt'
    if intermediate.exists():
        if not verify_intermediate_values(intermediate):
            all_passed = False
    else:
        print(f"\nIntermediate values file not found: {intermediate}")
    
    print("\n" + "=" * 60)
    if all_passed:
        print("All KAT verifications PASSED!")
    else:
        print("Some KAT verifications FAILED!")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == '__main__':
    exit(main())
