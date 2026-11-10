# DNS wire benchmarks

## What is compared

The standalone `comparison/` workspace compares the published `domain 0.12.3`
wire APIs with `zdwire`, using identical packets and caller-buffer outputs.
`domain` has default features disabled. Its resolver, networking, cache, and
cryptographic features are absent. `Cargo.lock` pins the comparison dependencies;
the published `zdwire` dependency tree remains empty.

The benchmark has five independent lanes:

| Lane | Work performed by both implementations |
| --- | --- |
| `raw` | Read questions and every RR header, validate and expand owner names, borrow opaque RDATA. |
| `typed` | Perform the same traversal, parse supported RDATA, expand embedded names, and visit TXT strings and EDNS options. |
| `reject` | Attempt the same raw traversal on an invalid name and return an error. |
| `encode-plain` | Encode questions and typed records without name compression into a reusable caller buffer. |
| `encode-compressed` | Encode the same inputs with a 24-entry bounded compression table. |

Full semantic snapshots compare header bytes, question fields, section identity,
every expanded name byte, every RR field, and uncompressed RDATA before timing.
Encoding cases must produce byte-identical messages. The timed traversals retain
a digest of every field and every label/string/option; they sample payload
length and endpoints rather than hashing all payload bytes. Consequently, the
65,535-byte opaque-RDATA parse is a framing benchmark: it does not scan or copy
the opaque payload. Its latency must not be described as memory bandwidth.

The domain parse path is `Message::from_slice`, question iteration,
`QuestionSection::next_section`, sequential `RecordSection` iteration, and
`ParsedRecord::into_record::<UnknownRecordData<_>>` or
`ParsedRecord::into_any_record::<AllRecordData<_, _>>`. Section traversal is
sequential. Domain's name parser validates compressed names, and its label
iterator expands them. There is no header-only versus fully parsed comparison.

The serialization path uses `domain::base::MessageBuilder` with a small adapter
implementing its documented `OctetsBuilder`, `Truncate`, and `Composer` traits
over `&mut [u8]`. Compression uses domain's `StaticCompressor`, which has 24
entries; `zdwire` receives 24 `CompressionEntry` slots. Both output buffers are
allocated once by the harness and reused. Timed paths have no heap allocation,
formatting, network activity, or test fixture construction. Error values are
discarded without allocating error strings.

## Reproduce

Run from the repository root with a stable Rust toolchain:

```sh
rustc -Vv
cargo test --manifest-path comparison/Cargo.toml --locked
ZD_BENCH_MS=50 ZD_BENCH_SAMPLES=11 \
  cargo run --release --manifest-path comparison/Cargo.toml --locked --bin compare \
  > comparison/results/local.csv
```

The release profile uses thin LTO and one codegen unit for both libraries. There
are no CPU-specific `RUSTFLAGS`. Inputs are deterministic and built by
`comparison/src/fixtures.rs`, independently of either encoder. The harness
calibrates an iteration count per implementation, alternates measurement order,
and reports the median of eleven samples. CSV includes interquartile spread as a
percentage of the median; smaller differences deserve particular caution on
shared hosts.

The corpus contains a normal A query, a minimal A answer, 64 uncompressed
answers, 32 compressed CNAME/address pairs, 64 TXT records with eight 80-byte
strings each, EDNS options, 512 repeated compressed owners, a packet of exactly
65,535 bytes, and a mixed packet containing every supported RR type and all
three RR sections. Invalid inputs cover self-pointers, forward pointers,
multi-node loops, out-of-bounds and truncated pointers, reserved label forms,
truncated labels, and overlong expanded names.

## Equivalence boundaries

`zdwire` limits a name to 32 pointer hops; domain 0.12.3 allows up to 255. The
comparison tests explicitly cover this policy difference. Deep chains accepted
only by domain are not used to claim a speedup. Both implementations reject
the malformed compression fixtures in the timed corpus.

Strict whole-message validation is separate from both timed parse lanes.
`MessageView::validate()` additionally checks the exact packet end, EDNS
placement and uniqueness, supported RDATA lengths, and field-specific rules.
The raw lane intentionally leaves RDATA opaque in both libraries. The typed
lane uses valid inputs within the common behavior. In particular, `zdwire`
rejects an empty CAA tag and a compressed SRV target; the comparison suite
records the empty-CAA difference explicitly. CAA lengths through 255 bytes are
included in differential tests.

The suite also compares 512 deterministic queries with arbitrary binary label
octets, 512 generated responses, every prefix of the mixed packet, and 10,000
mutated packets using equivalent raw-wire acceptance and digests. These tests
complement the core crate's RFC vectors, round trips, Miri, and fuzz target.

## Source analysis

The independent implementation focuses on the overlapping wire layer. Domain's
`ParsedName::parse_ref` separates literal labels from pointer traversal, stores
a borrowed packet reference, validates expanded length, and normalizes a name
that begins with a pure pointer to its target. Its bounded `StaticCompressor`
searches up to 24 previous name offsets. `zdwire` keeps borrowed slices and
compact section state, uses precise offset-bearing errors, and uses a
caller-sized compression table with bounded lookup work. These design facts
identify mechanisms; measured timings establish their performance consequences.

Primary references:

- [domain 0.12.3 name parser source](https://docs.rs/crate/domain/0.12.3/source/src/base/name/parsed.rs)
- [domain 0.12.3 message parser source](https://docs.rs/crate/domain/0.12.3/source/src/base/message.rs)
- [domain 0.12.3 message builder and StaticCompressor source](https://docs.rs/crate/domain/0.12.3/source/src/base/message_builder.rs)
- [domain 0.12.3 crate and feature configuration](https://crates.io/crates/domain/0.12.3)
- [RFC 1035 §4: DNS messages and compression](https://www.rfc-editor.org/rfc/rfc1035#section-4)
- [RFC 2782: SRV target encoding](https://www.rfc-editor.org/rfc/rfc2782)
- [RFC 6891 §6: EDNS OPT](https://www.rfc-editor.org/rfc/rfc6891#section-6)
- [RFC 8659 §4.1: CAA wire format](https://www.rfc-editor.org/rfc/rfc8659#section-4.1)

## Evidence review

| Question | Evidence and boundary |
| --- | --- |
| Does the comparison isolate wire operations? | Default features are disabled; fixed-buffer encoding and raw/typed parsing are timed separately. |
| Can another developer reproduce it? | Complete commands, deterministic generators, exact dependencies, profile, sample durations, and raw CSV are provided. |
| Is equal output checked? | Full canonical snapshots and byte-identical encoded packets are checked before timing. |
| Are difficult inputs represented? | Compressed names, TXT, EDNS, near-limit packets, arbitrary octets, truncation, corruption, and bounded malicious-name rejection are covered. |
| Do the results generalize without qualification? | Results describe this compiler, host, corpus, and API use. CPU contention, code generation, table occupancy, and message distributions can change the ratios. |
