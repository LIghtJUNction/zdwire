# Security

## Parsing limits

`zdwire` treats every input byte as untrusted. The core uses safe Rust, caller
buffers, checked lengths, and iterative name traversal. It accepts messages of
at most 65,535 bytes, labels of at most 63 bytes, expanded names of at most 255
bytes, and at most 32 compression-pointer hops per name. A limit violation is
an error with the offending packet offset. A valid but deeper pointer chain
is rejected intentionally.

Compression pointers must point backward. Self references, forward references,
cycles, truncated pointers, reserved label encodings, and out-of-range targets
fail without recursion. Borrowed names refer to immutable input. Unknown RDATA
is opaque: transferring it into a different packet does not relocate embedded
compression pointers from record formats that permit them.

`MessageView::parse` checks the header and message size. Iteration checks fields
as they are reached. Use `MessageView::validate` when the complete message,
including known RDATA, section placement, EDNS, and trailing bytes, must be
validated before use.

## Reproduction

```sh
cargo test --test security
cargo +nightly miri test --test security
cargo run --release --manifest-path fuzz/Cargo.toml -- --iterations 1000000 --seed 4277009102
RUSTFLAGS='-Zsanitizer=address' cargo +nightly run --release --manifest-path fuzz/Cargo.toml --target x86_64-unknown-linux-gnu -- --iterations 1000000 --seed 4277009102
```

The standalone fuzz driver uses deterministic mutations and generated wire
messages. Supply `--input packet.bin` to replay a saved packet. Its code and
random seed are recorded so failures can be reproduced without a third-party
fuzzing framework. CI timeouts provide a second termination boundary. Miri and
AddressSanitizer complement protocol tests; they do not establish the absence
of all implementation defects.

## Reporting

Use the repository's private vulnerability reporting feature when available:
<https://github.com/LIghtJUNction/zdwire/security/advisories/new>.
Include the smallest reproducing packet, the crate version, and the failing
command. Avoid including captured packets with private names or addresses.
