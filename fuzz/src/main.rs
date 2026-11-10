//! Deterministic byte mutation harness with no third-party dependencies.
use std::{env, fs, process};
use zdwire::{
    Class, CompressionEntry, Header, MessageBuilder, MessageView, Name, RecordData, Section, Type,
};

const QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01";
const ANSWER: &[u8] = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01";
const TXT: &[u8] = b"\0\0\x81\x80\0\0\0\x01\0\0\0\0\0\0\x10\0\x01\0\0\0\x3c\0\x08\x03abc\0\x02de";
const EDNS: &[u8] =
    b"\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\x29\x04\xd0\0\0\x80\0\0\x0c\0\x0a\0\x08abcdefgh";
const LOOP: &[u8] = b"\0\0\0\0\0\x01\0\0\0\0\0\0\xc0\x0c\0\x01\0\x01";

fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn name_properties(name: Name<'_>) {
    let mut output = [0u8; 255];
    let length = name.write_uncompressed(&mut output).unwrap();
    assert_eq!(length, name.wire_len());
    let plain = Name::from_wire(&output[..length]).unwrap();
    assert!(name == plain);
    assert_eq!(
        name.labels().collect::<Vec<_>>(),
        plain.labels().collect::<Vec<_>>()
    );
    assert!(name.labels().count() <= 127);
}

fn encode_properties(bytes: &[u8]) {
    let mut output = [0xacu8; 512];
    let mut table = [CompressionEntry::EMPTY; 16];
    let name = Name::parse(bytes, 0)
        .map(|pair| pair.0)
        .unwrap_or_else(|_| Name::from_wire(b"\0").unwrap());
    let mut builder =
        MessageBuilder::with_compression(&mut output, Header::new(0, 0), &mut table).unwrap();
    let _ = builder.add_question(name, Type::A, Class::IN);
    let snapshot = builder.as_bytes().to_vec();
    let data = match bytes.first().copied().unwrap_or(0) % 5 {
        0 => RecordData::Txt(bytes),
        1 => RecordData::Unknown {
            rr_type: Type(65000),
            rdata: bytes,
        },
        2 => RecordData::Cname(name),
        3 => RecordData::Caa {
            flags: 0,
            tag: &bytes[..bytes.len().min(16)],
            value: bytes,
        },
        _ => RecordData::Srv {
            priority: 0,
            weight: 1,
            port: 53,
            target: name,
        },
    };
    if builder
        .add_record(Section::Answer, name, Class::IN, 0, data)
        .is_err()
    {
        assert_eq!(builder.as_bytes(), snapshot);
    }
    let snapshot = builder.as_bytes().to_vec();
    if builder.add_opt(1232, 0, 0, 0, bytes).is_err() {
        assert_eq!(builder.as_bytes(), snapshot);
    }
    MessageView::parse(builder.as_bytes())
        .unwrap()
        .validate()
        .unwrap();
}

fn exercise(bytes: &[u8]) {
    encode_properties(bytes);
    // Include extreme offsets to exercise public arithmetic boundaries.
    for offset in [
        0,
        12,
        bytes.len() / 2,
        bytes.len().saturating_sub(1),
        usize::MAX,
    ] {
        if let Ok((name, end)) = Name::parse(bytes, offset) {
            assert!(end <= bytes.len());
            name_properties(name);
        }
    }
    if let Ok(view) = MessageView::parse(bytes) {
        let _ = view.validate();
        for (index, question) in view.questions().enumerate() {
            assert!(index <= 65_535, "question iterator did not terminate");
            if let Ok(question) = question {
                name_properties(question.name);
            }
        }
        for (index, record) in view.records().enumerate() {
            assert!(index <= 196_605, "record iterator did not terminate");
            if let Ok(record) = record {
                let _ = record.data();
                name_properties(record.name);
            }
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: zdwire-fuzz [--iterations N] [--seed N] [--input FILE]");
    process::exit(2)
}

fn main() {
    let mut iterations = 100_000usize;
    let mut seed = 4_277_009_102u64;
    let mut input = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let value = arguments.next().unwrap_or_else(|| usage());
        match argument.as_str() {
            "--iterations" => iterations = value.parse().unwrap_or_else(|_| usage()),
            "--seed" => seed = value.parse().unwrap_or_else(|_| usage()),
            "--input" => input = Some(value),
            _ => usage(),
        }
    }
    if let Some(path) = input {
        let bytes = fs::read(path).expect("read replay input");
        exercise(&bytes);
        println!("replay passed ({} bytes)", bytes.len());
        return;
    }
    assert_ne!(seed, 0, "xorshift seed must be nonzero");
    let initial_seed = seed;
    let fixtures = [QUERY, ANSWER, TXT, EDNS, LOOP, &[]];
    for bytes in fixtures {
        exercise(bytes);
    }
    let mut bytes = Vec::with_capacity(65_536);
    for iteration in 0..iterations {
        bytes.clear();
        if iteration % 7 == 0 {
            let length = match iteration % 35 {
                0 => 65_536,
                7 => 65_535,
                14 => 4096,
                _ => (random(&mut seed) as usize) & 511,
            };
            bytes.resize(length, 0);
            for byte in &mut bytes {
                *byte = random(&mut seed) as u8;
            }
        } else {
            bytes.extend_from_slice(fixtures[random(&mut seed) as usize % fixtures.len()]);
            for _ in 0..1 + random(&mut seed) % 8 {
                let position = random(&mut seed) as usize % (bytes.len() + 1);
                match random(&mut seed) % 6 {
                    0 if position < bytes.len() => bytes[position] ^= 1 << (random(&mut seed) % 8),
                    1 if position < bytes.len() => bytes[position] = random(&mut seed) as u8,
                    2 => bytes.truncate(position),
                    3 if bytes.len() < 65_535 => bytes.insert(position, random(&mut seed) as u8),
                    4 if position < bytes.len() => {
                        bytes.remove(position);
                    }
                    _ if position + 1 < bytes.len() => {
                        bytes[position] = 0xc0 | (random(&mut seed) as u8 & 0x3f);
                        bytes[position + 1] = random(&mut seed) as u8;
                    }
                    _ => {}
                }
            }
        }
        exercise(&bytes);
    }
    println!("{iterations} mutation cases passed; seed={initial_seed}");
}
