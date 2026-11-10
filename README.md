# zdwire

DNS wire parsing and encoding with **zero dependencies, zero heap allocation,
and safe Rust**. The library is always `#![no_std]` and uses only `core`.
Stable Rust **1.74** is the minimum supported version.

`zdwire` handles the bytes of a DNS message. Transport, resolvers, caches,
DNSSEC verification, and a command-line application are outside its scope.
The output buffer, optional compression table, and input lifetime belong to
the caller.

## Encode a query

```rust
use zdwire::{Class, Header, MessageBuilder, Name, Type};

let name = Name::from_wire(b"\x03www\x07example\x03com\0")?;
let mut output = [0u8; 512];
let mut message = MessageBuilder::new(&mut output, Header::new(0x1234, Header::RD))?;
message.add_question(name, Type::A, Class::IN)?;
let packet = message.finish(); // Only the initialized prefix; 33 bytes here.
# Ok::<(), zdwire::Error>(())
```

For text input, `encode_name("www.example.com.", &mut name_buffer)` returns
the used length. `Name::from_wire(&name_buffer[..len])` then borrows it. Text
conversion understands escaped dots/backslashes and three-digit decimal octets;
it does not perform IDNA conversion. Wire labels may contain arbitrary bytes.

## Parse without allocation

```rust
use zdwire::{MessageView, Rdata};
# let packet = [0u8; 12];

let message = MessageView::parse(&packet)?;
let header = message.header();
let mut questions = message.questions();
for question in questions.by_ref() {
    let question = question?;
    for label in question.name.labels() {
        // `label` is a borrowed &[u8]; the terminating root is omitted.
        let _ = label;
    }
}
// Reuse the cursor: consumed questions are not scanned again.
for record in questions.into_records()? {
    let record = record?;
    match record.data()? {
        Rdata::A(address) => { let _ = address; }
        Rdata::Txt(text) => {
            for string in text.iter() { let _ = string; }
        }
        _ => {}
    }
}
# Ok::<(), zdwire::Error>(())
```

`MessageView::parse` checks the 12-byte header and message-size limit. Question
and record iterators validate the fields they visit; `Record::data` validates
the requested typed RDATA. Unknown types retain their original bytes.
`MessageView::parse_strict` or `message.validate()` checks the complete packet,
including typed RDATA, EDNS placement and uniqueness, and trailing bytes.
Choose strict validation at a boundary that requires a complete valid packet;
choose streaming access when the application consumes and handles each result.

`records()` traverses all three RR sections in one pass. `answers()`,
`authorities()`, and `additionals()` locate an individual section by scanning
the preceding sections; repeated calls repeat that scan. All fallible iterators
stop permanently after their first error.

## Encode a compressed response

```rust
use zdwire::{Class, CompressionEntry, Header, MessageBuilder, Name, RecordData, Section, Type};

let name = Name::from_wire(b"\x07example\x03com\0")?;
let mut output = [0u8; 512];
let mut table = [CompressionEntry::EMPTY; 64];
let mut message = MessageBuilder::with_compression(
    &mut output, Header::new(0x1234, Header::QR | Header::AA), &mut table,
)?;
message.add_question(name, Type::A, Class::IN)?;
message.add_record(Section::Answer, name, Class::IN, 300, RecordData::A([192, 0, 2, 1]))?;
message.add_opt(1232, 0, 0, 0x8000, &[])?;
let packet = message.finish();
# Ok::<(), zdwire::Error>(())
```

Append questions, answers, authorities, then additionals. Empty sections can be
skipped. The builder owns section counts and starts them at zero, preserving
the supplied header's ID and flags. `add_opt` places the sole OPT in Additional.
Unknown EDNS versions, flags, and option payloads remain accessible as wire data.

Each append validates input and computes its size before changing the output.
On `BufferTooSmall { needed }`, `needed` is the exact total buffer length needed
for that append with the current dictionary. Earlier bytes, counts, section
position, and dictionary remain unchanged. `len()` and `finish().len()` give the
actual used length. The builder does not resize or allocate memory; a caller
that changes buffers rebuilds the packet in its new buffer.

The compression table is a bounded direct-mapped dictionary. Collisions can
reduce compression but cannot change name bytes. Pointers use only earlier,
uncompressed label boundaries below offset 16,384. Generated names therefore
have at most one pointer hop. Label case is preserved. An empty table disables
compression. A 256-entry table occupies 2 KiB on common 32/64-bit targets.

## Wire coverage

| Data | Representation |
|---|---|
| Header | All ID, flags, opcode, response code, and count bits retained |
| Questions | Borrowed name, numeric type and class |
| Answer / Authority / Additional | Sequential or section-specific iterators |
| A / AAAA | Borrowed address bytes on decode; fixed arrays on encode |
| CNAME / NS / PTR | Validated names with RFC 1035 compression |
| MX / SOA | Numeric fields and packet-relative compressed names |
| TXT | Separate length-prefixed byte strings, including empty strings |
| SRV | Priority, weight, port, uncompressed target |
| CAA | Flags, 1–255 ASCII alphanumeric tag bytes, opaque value |
| OPT | UDP payload size, extended response code, version, flags, options |
| Unknown RR | Type code and exact raw RDATA |

Names compare using ASCII case folding. `eq_case_sensitive` compares original
octets. `write_uncompressed` writes into caller memory; `as_uncompressed` borrows
a contiguous expanded representation when the packet already contains one.
`Display` uses escaped DNS presentation notation without allocating inside the
library.

Opaque RDATA is not interpreted or rewritten. RFC 3597-compatible unknown data
can be copied as-is; legacy unknown formats containing compression pointers
need type-specific relocation by the caller. `RecordData::Unknown` rejects
types that already have a typed encoder so they cannot bypass its checks.

## Error and work limits

`Error { kind, offset }` gives a specific category and an absolute message-byte
offset. A truncated field reports its first missing byte. Text-name errors
refer to input text; encoding capacity errors refer to the output. The core
contains no `unsafe`, recursion, mutable globals, allocation, or input-sized
stack arrays.

| Limit | Policy |
|---|---|
| Message | At most 65,535 bytes, excluding transport framing |
| Label | At most 63 bytes |
| Expanded name | At most 255 bytes, including length bytes and root |
| Compression | At most 32 hops per name; backward pointers only |
| Pointer cycles | Self-reference and repeated pointer positions rejected |
| Unsupported label types | Extended/reserved label encodings rejected |
| RDATA boundary | Inline fields stay inside RDLENGTH; pointers use the packet |
| EDNS | One OPT, literal root owner, Additional section only |

The 32-hop cap deliberately rejects some otherwise valid, unusually deep
compression chains. This is an explicit resource policy, reported as
`PointerLimit`. See [SECURITY.md](https://github.com/LIghtJUNction/zdwire/blob/main/SECURITY.md) for the threat model.

## Performance and reproducibility

The isolated [comparison/](https://github.com/LIghtJUNction/zdwire/tree/main/comparison) project pins NLnet Labs `domain 0.12.3`
with default features disabled. It checks semantic equality before timing,
then measures raw-record traversal, typed traversal, and encoding into caller
buffers. The root crate has **no normal, build, dev, optional, or target-specific
dependencies**; the comparison dependencies never enter its package.

```sh
cargo test --locked
cargo test --locked --manifest-path comparison/Cargo.toml
ZD_BENCH_MS=50 ZD_BENCH_SAMPLES=11 cargo run --release --locked --manifest-path comparison/Cargo.toml
```

Read [docs/benchmark.md](https://github.com/LIghtJUNction/zdwire/blob/main/docs/benchmark.md) for complete commands, compiler/CPU
details, timings, equivalence boundaries, and scenarios where either library
is faster. Performance claims apply to those measured paths and fixtures.

## Verification

```sh
cargo +1.74.0 test --locked --all-targets
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --doc
cargo doc --locked --no-deps
cargo check --locked --lib --target wasm32-unknown-unknown
cargo check --locked --lib --target thumbv7em-none-eabi
cargo +nightly miri test --locked --test security
cargo run --release --locked --manifest-path fuzz/Cargo.toml -- --iterations 200000 --seed 4277009102
python3 scripts/check-package.py
python3 -m unittest discover -s scripts -p 'test_*.py' -v
cargo package --locked
cargo publish --locked --dry-run
```

The tests include the RFC 1035 compression example, every supported RR,
round trips, exact error offsets, bounded malicious pointers, truncated data,
binary names, random malformed packets, and transactional output failures.
The independent fuzz driver uses deterministic mutations and an optional input
corpus; CI also runs it under AddressSanitizer. This is mutation fuzzing, not a
claim of exhaustive verification or coverage-guided fuzzing.

## CI and release

CI runs MSRV and stable tests on Linux, Windows, and macOS; it also checks
formatting, Clippy, documentation, WASM, embedded `no_std`, package contents,
publish dry-run, differential tests, Miri, and sanitizer fuzzing.

Configure the repository secret **`CARGO_REGISTRY_TOKEN`** with permission to
publish this crate. In **Actions → Release → Run workflow**, select the default
branch and `patch`, `minor`, or `major`. `current` publishes the existing version
or resumes an interrupted initial release without another version increment.

The workflow updates the package version and all relevant lockfiles, pushes the
version commit, validates its exact SHA through the complete CI workflow, then
creates a version tag, publishes to crates.io, and creates a GitHub Release.
Published versions are detected and never uploaded again. A release-event run
also checks tag/version agreement and that the tag commit belongs to the default
branch. All publishing steps stay in the same run, so `GITHUB_TOKEN` event
suppression cannot break the publication chain. Credentials remain environment
variables and are never printed by the release scripts.

## Standards

- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035): message layout, labels, compression, and original RR formats.
- [RFC 3596](https://www.rfc-editor.org/rfc/rfc3596): AAAA wire data.
- [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782): SRV and its uncompressed target.
- [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891): EDNS OPT fields and option framing.
- [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659): CAA wire syntax.
- [RFC 3597](https://www.rfc-editor.org/rfc/rfc3597): handling unknown RR types.

MIT licensed. See [LICENSE](https://github.com/LIghtJUNction/zdwire/blob/main/LICENSE).
