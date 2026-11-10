# Changelog

## 0.1.0

- Zero-dependency, core-only DNS message parsing and caller-buffer encoding.
- Validated borrowed names, bounded RFC 1035 compression, and fused iterators.
- Typed A, AAAA, CNAME, NS, PTR, MX, TXT, SOA, SRV, CAA, and basic EDNS OPT.
- Transactional encoding with exact capacity errors and caller-owned compression.
- RFC vectors, round trips, adversarial inputs, domain differential comparisons,
  Miri, sanitizer mutation fuzzing, and reproducible benchmarks.
- Rust 1.74 MSRV, Linux/macOS/Windows CI, WASM and embedded compile checks.
- Default-branch version bump and resumable Tag/crates.io/GitHub Release workflow.
