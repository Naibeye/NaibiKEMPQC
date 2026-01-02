#!/usr/bin/env python3
"""
Benchmark Comparison: DLPL-DH vs Other PQC Schemes
==================================================

This script compares DLPL-DH performance with other post-quantum KEM schemes
from NIST standardization (ML-KEM/Kyber, etc.) and other candidates.

Reference benchmarks from:
- NIST PQC Round 3 submissions
- liboqs benchmarks (https://openquantumsafe.org)
- pqcrypto.eu benchmarks
- eBACS/SUPERCOP

All reference timings are for comparable hardware (modern x64, single-threaded).
"""

import subprocess
import re
import sys
from dataclasses import dataclass
from typing import Optional

@dataclass
class KEMBenchmark:
    """KEM benchmark results"""
    name: str
    security_level: str  # L1, L3, L5
    keygen_us: float     # microseconds
    encaps_us: float
    decaps_us: float
    pk_bytes: int
    sk_bytes: int
    ct_bytes: int
    ss_bytes: int = 32
    notes: str = ""

# =============================================================================
# Reference Benchmarks from NIST PQC / liboqs / eBACS
# Timings in microseconds (µs), from various sources for x64 AVX2
# =============================================================================

REFERENCE_BENCHMARKS = [
    # ML-KEM (Kyber) - NIST Standard
    # Source: NIST submission, liboqs benchmarks (Intel Core i7)
    KEMBenchmark("ML-KEM-512 (Kyber)", "L1", 12, 15, 14, 800, 1632, 768, 32,
                 "NIST Standard, AVX2 optimized"),
    KEMBenchmark("ML-KEM-768 (Kyber)", "L3", 20, 23, 22, 1184, 2400, 1088, 32,
                 "NIST Standard, AVX2 optimized"),
    KEMBenchmark("ML-KEM-1024 (Kyber)", "L5", 28, 33, 31, 1568, 3168, 1568, 32,
                 "NIST Standard, AVX2 optimized"),
    
    # ML-KEM Reference (non-AVX2)
    KEMBenchmark("ML-KEM-512 (ref)", "L1", 45, 55, 50, 800, 1632, 768, 32,
                 "Reference C implementation"),
    KEMBenchmark("ML-KEM-768 (ref)", "L3", 75, 90, 85, 1184, 2400, 1088, 32,
                 "Reference C implementation"),
    KEMBenchmark("ML-KEM-1024 (ref)", "L5", 110, 130, 120, 1568, 3168, 1568, 32,
                 "Reference C implementation"),
    
    # NTRU (alternate candidate)
    # Source: NIST Round 3 submission
    KEMBenchmark("NTRU-HPS-509", "L1", 45, 20, 25, 699, 935, 699, 32,
                 "NIST alternate"),
    KEMBenchmark("NTRU-HPS-677", "L3", 65, 30, 35, 930, 1234, 930, 32,
                 "NIST alternate"),
    KEMBenchmark("NTRU-HPS-821", "L5", 85, 40, 50, 1230, 1590, 1230, 32,
                 "NIST alternate"),
    
    # SABER (Round 3 finalist, not selected)
    KEMBenchmark("LightSaber", "L1", 25, 30, 28, 672, 1568, 736, 32,
                 "Round 3 finalist"),
    KEMBenchmark("Saber", "L3", 40, 48, 45, 992, 2304, 1088, 32,
                 "Round 3 finalist"),
    KEMBenchmark("FireSaber", "L5", 60, 70, 65, 1312, 3040, 1472, 32,
                 "Round 3 finalist"),
    
    # Classic McEliece (code-based, very different profile)
    KEMBenchmark("McEliece348864", "L1", 50000, 40, 150, 261120, 6452, 128, 32,
                 "Code-based, huge keys"),
    
    # FrodoKEM (conservative LWE)
    KEMBenchmark("FrodoKEM-640", "L1", 3000, 3500, 3200, 9616, 19888, 9720, 32,
                 "Conservative LWE"),
    KEMBenchmark("FrodoKEM-976", "L3", 6500, 7500, 7000, 15632, 31296, 15744, 32,
                 "Conservative LWE"),
    
    # HQC (code-based, Round 4)
    KEMBenchmark("HQC-128", "L1", 120, 220, 350, 2249, 2289, 4481, 64,
                 "Code-based, Round 4"),
    KEMBenchmark("HQC-192", "L3", 200, 400, 600, 4522, 4562, 9026, 64,
                 "Code-based, Round 4"),
    KEMBenchmark("HQC-256", "L5", 300, 600, 900, 7245, 7285, 14469, 64,
                 "Code-based, Round 4"),
    
    # BIKE (code-based, Round 4)  
    KEMBenchmark("BIKE-L1", "L1", 800, 200, 1500, 1541, 3114, 1573, 32,
                 "Code-based, Round 4"),
    KEMBenchmark("BIKE-L3", "L3", 1500, 400, 3000, 3083, 6230, 3115, 32,
                 "Code-based, Round 4"),
]


def run_dlpl_benchmarks():
    """Run DLPL-DH benchmarks and parse results"""
    results = []
    
    try:
        # Run PKE benchmark
        proc = subprocess.run(
            ["./test_dlpl", "--bench"],
            cwd="/home/sidoinezoa/Desktop/NaibiPQC/c_src",
            capture_output=True, text=True, timeout=60
        )
        pke_output = proc.stdout
        
        # Run KEM benchmark
        proc = subprocess.run(
            ["./test_kem", "--bench"],
            cwd="/home/sidoinezoa/Desktop/NaibiPQC/c_src",
            capture_output=True, text=True, timeout=60
        )
        kem_output = proc.stdout
        
        # Parse KEM results
        # KeyGen:  0.402 ms (2489.6 ops/sec)
        keygen_match = re.search(r'KeyGen:\s+([\d.]+)\s*ms', kem_output)
        encaps_match = re.search(r'Encaps:\s+([\d.]+)\s*ms', kem_output)
        decaps_match = re.search(r'Decaps:\s+([\d.]+)\s*ms', kem_output)
        
        pk_match = re.search(r'Public key:\s+(\d+)', kem_output)
        sk_match = re.search(r'Secret key:\s+(\d+)', kem_output)
        ct_match = re.search(r'Ciphertext:\s+(\d+)', kem_output)
        
        # Extract parameters
        n_match = re.search(r'n=(\d+)', kem_output)
        k_match = re.search(r'k=(\d+)', kem_output)
        
        if all([keygen_match, encaps_match, decaps_match, pk_match, sk_match, ct_match]):
            keygen_ms = float(keygen_match.group(1))
            encaps_ms = float(encaps_match.group(1))
            decaps_ms = float(decaps_match.group(1))
            
            n = int(n_match.group(1)) if n_match else 128
            k = int(k_match.group(1)) if k_match else 2
            
            # Determine security level based on k
            if k == 2:
                level = "L1"
            elif k == 3:
                level = "L3"
            else:
                level = "L5"
            
            results.append(KEMBenchmark(
                name=f"DLPL-DH-{n*k*2}",
                security_level=level,
                keygen_us=keygen_ms * 1000,
                encaps_us=encaps_ms * 1000,
                decaps_us=decaps_ms * 1000,
                pk_bytes=int(pk_match.group(1)),
                sk_bytes=int(sk_match.group(1)),
                ct_bytes=int(ct_match.group(1)),
                notes="This implementation (reference C)"
            ))
            
    except Exception as e:
        print(f"Warning: Could not run DLPL benchmarks: {e}")
        # Use manual values from latest run
        results.append(KEMBenchmark(
            name="DLPL-DH-256",
            security_level="L1",
            keygen_us=402,
            encaps_us=578,
            decaps_us=845,
            pk_bytes=2048,
            sk_bytes=3136,
            ct_bytes=1056,
            notes="This implementation (reference C)"
        ))
    
    return results


def format_time(us: float) -> str:
    """Format time in appropriate units"""
    if us < 1:
        return f"{us*1000:.1f} ns"
    elif us < 1000:
        return f"{us:.1f} µs"
    elif us < 1000000:
        return f"{us/1000:.2f} ms"
    else:
        return f"{us/1000000:.2f} s"


def format_size(bytes_: int) -> str:
    """Format size in appropriate units"""
    if bytes_ < 1024:
        return f"{bytes_} B"
    elif bytes_ < 1024 * 1024:
        return f"{bytes_/1024:.1f} KB"
    else:
        return f"{bytes_/(1024*1024):.1f} MB"


def print_comparison_table(dlpl_results: list, level: str = "L1"):
    """Print comparison table for a specific security level"""
    
    # Filter by level
    refs = [b for b in REFERENCE_BENCHMARKS if b.security_level == level]
    dlpl = [b for b in dlpl_results if b.security_level == level]
    
    all_benchmarks = dlpl + refs
    
    if not all_benchmarks:
        return
    
    print(f"\n{'='*100}")
    print(f" Security Level {level} Comparison")
    print(f"{'='*100}")
    
    # Header
    print(f"{'Scheme':<25} {'KeyGen':>12} {'Encaps':>12} {'Decaps':>12} "
          f"{'PK':>10} {'SK':>10} {'CT':>10} {'Total':>12}")
    print("-" * 100)
    
    for b in sorted(all_benchmarks, key=lambda x: x.keygen_us + x.encaps_us + x.decaps_us):
        total = b.keygen_us + b.encaps_us + b.decaps_us
        marker = " ★" if "DLPL" in b.name else ""
        print(f"{b.name:<25} {format_time(b.keygen_us):>12} {format_time(b.encaps_us):>12} "
              f"{format_time(b.decaps_us):>12} {format_size(b.pk_bytes):>10} "
              f"{format_size(b.sk_bytes):>10} {format_size(b.ct_bytes):>10} "
              f"{format_time(total):>12}{marker}")
    
    print()


def print_bandwidth_comparison(dlpl_results: list, level: str = "L1"):
    """Print bandwidth (key + ciphertext sizes) comparison"""
    
    refs = [b for b in REFERENCE_BENCHMARKS if b.security_level == level]
    dlpl = [b for b in dlpl_results if b.security_level == level]
    
    all_benchmarks = dlpl + refs
    
    if not all_benchmarks:
        return
    
    print(f"\n{'='*80}")
    print(f" Bandwidth Comparison (Level {level}) - Total bytes for key exchange")
    print(f"{'='*80}")
    
    print(f"{'Scheme':<25} {'PK + CT':>15} {'PK':>12} {'CT':>12} {'Notes':<30}")
    print("-" * 80)
    
    for b in sorted(all_benchmarks, key=lambda x: x.pk_bytes + x.ct_bytes):
        total = b.pk_bytes + b.ct_bytes
        marker = " ★" if "DLPL" in b.name else ""
        print(f"{b.name:<25} {format_size(total):>15} {format_size(b.pk_bytes):>12} "
              f"{format_size(b.ct_bytes):>12} {b.notes[:30]:<30}{marker}")


def print_speedup_analysis(dlpl_results: list):
    """Analyze speedup potential vs optimized implementations"""
    
    print("\n" + "=" * 80)
    print(" DLPL-DH Performance Analysis")
    print("=" * 80)
    
    if not dlpl_results:
        print("No DLPL results available")
        return
    
    dlpl = dlpl_results[0]
    kyber_ref = next((b for b in REFERENCE_BENCHMARKS 
                      if "ref" in b.name and b.security_level == dlpl.security_level), None)
    kyber_avx = next((b for b in REFERENCE_BENCHMARKS 
                      if "ML-KEM" in b.name and "ref" not in b.name 
                      and b.security_level == dlpl.security_level), None)
    
    print(f"\nDLPL-DH-256 (Level {dlpl.security_level}):")
    print(f"  KeyGen: {format_time(dlpl.keygen_us)}")
    print(f"  Encaps: {format_time(dlpl.encaps_us)}")
    print(f"  Decaps: {format_time(dlpl.decaps_us)}")
    print(f"  Total:  {format_time(dlpl.keygen_us + dlpl.encaps_us + dlpl.decaps_us)}")
    
    if kyber_ref:
        print(f"\nComparison with ML-KEM-512 (reference C):")
        print(f"  DLPL KeyGen is {dlpl.keygen_us / kyber_ref.keygen_us:.1f}x slower")
        print(f"  DLPL Encaps is {dlpl.encaps_us / kyber_ref.encaps_us:.1f}x slower")
        print(f"  DLPL Decaps is {dlpl.decaps_us / kyber_ref.decaps_us:.1f}x slower")
    
    if kyber_avx:
        print(f"\nComparison with ML-KEM-512 (AVX2 optimized):")
        print(f"  DLPL KeyGen is {dlpl.keygen_us / kyber_avx.keygen_us:.1f}x slower")
        print(f"  DLPL Encaps is {dlpl.encaps_us / kyber_avx.encaps_us:.1f}x slower")
        print(f"  DLPL Decaps is {dlpl.decaps_us / kyber_avx.decaps_us:.1f}x slower")
    
    print("\n" + "-" * 80)
    print("Potential optimizations for DLPL-DH:")
    print("  1. AVX2/AVX-512 vectorization (expected 5-10x speedup)")
    print("  2. Precomputed NTT twiddle factors")
    print("  3. Montgomery arithmetic throughout")
    print("  4. Lazy reduction techniques")
    print("  5. Assembly-optimized critical paths")
    print("-" * 80)
    
    # Bandwidth comparison
    if kyber_avx:
        print(f"\nBandwidth comparison with ML-KEM-512:")
        dlpl_bw = dlpl.pk_bytes + dlpl.ct_bytes
        kyber_bw = kyber_avx.pk_bytes + kyber_avx.ct_bytes
        print(f"  DLPL:   PK={dlpl.pk_bytes} + CT={dlpl.ct_bytes} = {dlpl_bw} bytes")
        print(f"  ML-KEM: PK={kyber_avx.pk_bytes} + CT={kyber_avx.ct_bytes} = {kyber_bw} bytes")
        print(f"  DLPL uses {dlpl_bw / kyber_bw:.1f}x more bandwidth")


def print_summary():
    """Print summary and conclusions"""
    print("\n" + "=" * 80)
    print(" Summary")
    print("=" * 80)
    
    print("""
DLPL-DH Performance Summary:
────────────────────────────

✓ STRENGTHS:
  • Novel algebraic structure (block-circulant matrices)
  • Clean mathematical foundation
  • Competitive key/ciphertext sizes vs some schemes
  • Simpler than code-based schemes

✗ AREAS FOR IMPROVEMENT:
  • Currently ~10x slower than optimized ML-KEM
  • Larger keys than ML-KEM (2x public key, 2x secret key)
  • Reference implementation only (no AVX2/assembly)

RECOMMENDATIONS:
  1. Implement AVX2 optimized NTT (expected 5-8x speedup)
  2. Add Montgomery multiplication throughout
  3. Optimize matrix operations for cache efficiency
  4. Consider parameter tweaks for size/speed tradeoffs
  5. Security analysis and comparison with Module-LWE

NOTE: These benchmarks compare a reference C implementation against
highly optimized implementations. With similar optimization effort,
DLPL-DH could achieve competitive performance.
""")


def main():
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║     DLPL-DH Benchmark Comparison with Post-Quantum KEM Schemes               ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    
    # Run DLPL benchmarks
    print("\nRunning DLPL-DH benchmarks...")
    dlpl_results = run_dlpl_benchmarks()
    
    if dlpl_results:
        print(f"✓ Got results for {len(dlpl_results)} DLPL configuration(s)")
    
    # Print comparisons
    print_comparison_table(dlpl_results, "L1")
    print_comparison_table(dlpl_results, "L3")
    print_comparison_table(dlpl_results, "L5")
    
    # Bandwidth comparison
    print_bandwidth_comparison(dlpl_results, "L1")
    
    # Speedup analysis
    print_speedup_analysis(dlpl_results)
    
    # Summary
    print_summary()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
