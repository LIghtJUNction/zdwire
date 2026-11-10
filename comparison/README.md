# Wire-format comparison

This standalone workspace compares `zdwire` with `domain 0.12.3`. Its third-party
dependencies and lockfile do not enter the published `zdwire` crate.

```sh
cargo test --manifest-path comparison/Cargo.toml --locked
cargo run --release --manifest-path comparison/Cargo.toml --locked --bin compare
```

The program checks full semantic equality before measuring any fixture. It then
prints CSV rows for raw-record traversal, typed-RDATA traversal, malformed-name
rejection, uncompressed serialization, and compressed serialization. Ratios are
`domain_ns / zdwire_ns`; values above one favor `zdwire`.

For a longer run:

```sh
ZD_BENCH_MS=50 ZD_BENCH_SAMPLES=11 \
  cargo run --release --manifest-path comparison/Cargo.toml --locked --bin compare \
  > comparison/results/local.csv
```

`ZD_BENCH_MS` is the target duration of each sample for each implementation.
The default is nine samples of approximately 25 ms. Implementation order
alternates between samples. The CSV records medians and interquartile spread.

See [methodology and measured results](../docs/benchmark.md) for the shared
semantics, compiler and CPU information, and limitations.
