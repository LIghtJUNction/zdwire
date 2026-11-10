//! Deterministic wire fixtures built independently of either implementation.

#[derive(Clone)]
pub struct Fixture {
    pub name: &'static str,
    pub wire: Vec<u8>,
}

pub const WWW: &[u8] = b"\x03www\x07example\x03com\0";
pub const EXAMPLE: &[u8] = b"\x07example\x03com\0";
pub const MAIL: &[u8] = b"\x04mail\x07example\x03com\0";
pub const NS: &[u8] = b"\x02ns\x07example\x03com\0";
pub const HOSTMASTER: &[u8] = b"\x0ahostmaster\x07example\x03com\0";

fn u16_into(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn u32_into(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn header(q: u16, a: u16, ns: u16, ar: u16) -> Vec<u8> {
    let mut wire = Vec::new();
    for field in [0x4a6f, if a == 0 { 0x0100 } else { 0x8180 }, q, a, ns, ar] {
        u16_into(&mut wire, field);
    }
    wire
}

fn question(out: &mut Vec<u8>, name: &[u8], qtype: u16) {
    out.extend_from_slice(name);
    u16_into(out, qtype);
    u16_into(out, 1);
}

fn record(out: &mut Vec<u8>, owner: &[u8], rtype: u16, class: u16, ttl: u32, data: &[u8]) {
    out.extend_from_slice(owner);
    u16_into(out, rtype);
    u16_into(out, class);
    u32_into(out, ttl);
    u16_into(out, u16::try_from(data.len()).unwrap());
    out.extend_from_slice(data);
}

pub fn response(count: u16, compressed: bool) -> Vec<u8> {
    let mut wire = header(1, count, 0, 0);
    question(&mut wire, WWW, 1);
    for i in 0..count {
        record(
            &mut wire,
            if compressed { &[0xc0, 12] } else { WWW },
            1,
            1,
            300,
            &[192, 0, 2, i as u8],
        );
    }
    wire
}

pub fn txt_wire(strings: usize, string_len: usize) -> Vec<u8> {
    assert!(string_len <= 255);
    let mut bytes = Vec::with_capacity(strings * (string_len + 1));
    for i in 0..strings {
        bytes.push(string_len as u8);
        bytes.extend((0..string_len).map(|j| b'a' + ((i + j) % 26) as u8));
    }
    bytes
}

pub fn valid_fixtures() -> Vec<Fixture> {
    let mut query = header(1, 0, 0, 0);
    question(&mut query, WWW, 1);
    let mut small = header(0, 1, 0, 0);
    record(&mut small, &[0], 1, 1, 60, &[127, 0, 0, 1]);
    let mut compressed = header(1, 64, 0, 0);
    question(&mut compressed, WWW, 1);
    for i in 0..32 {
        record(&mut compressed, &[0xc0, 12], 5, 1, 300, b"\x04mail\xc0\x10");
        record(
            &mut compressed,
            b"\x04mail\xc0\x10",
            1,
            1,
            300,
            &[192, 0, 2, i],
        );
    }
    let mut txt = header(1, 64, 0, 0);
    question(&mut txt, EXAMPLE, 16);
    let text = txt_wire(8, 80);
    for _ in 0..64 {
        record(&mut txt, &[0xc0, 12], 16, 1, 600, &text);
    }
    let mut edns = header(1, 0, 0, 1);
    question(&mut edns, WWW, 1);
    let options = [
        0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 12, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    record(&mut edns, &[0], 41, 1232, 0x8000, &options);
    let mut near = header(0, 1, 0, 0);
    let raw: Vec<_> = (0..65512).map(|i| (i as u8).wrapping_mul(37)).collect();
    record(&mut near, &[0], 65280, 1, 0, &raw);
    assert_eq!(near.len(), 65535);
    vec![
        Fixture {
            name: "query",
            wire: query,
        },
        Fixture {
            name: "small-answer",
            wire: small,
        },
        Fixture {
            name: "64-answers",
            wire: response(64, false),
        },
        Fixture {
            name: "compressed-cname",
            wire: compressed,
        },
        Fixture {
            name: "64-txt",
            wire: txt,
        },
        Fixture {
            name: "edns",
            wire: edns,
        },
        Fixture {
            name: "512-repeated",
            wire: response(512, true),
        },
        Fixture {
            name: "65535-byte",
            wire: near,
        },
        Fixture {
            name: "all-types",
            wire: all_types(),
        },
    ]
}

pub fn all_types() -> Vec<u8> {
    let mut wire = header(1, 10, 1, 2);
    question(&mut wire, EXAMPLE, 255);
    let owner = [0xc0, 12];
    record(&mut wire, &owner, 1, 1, 300, &[192, 0, 2, 17]);
    record(
        &mut wire,
        &owner,
        28,
        1,
        301,
        &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    );
    record(&mut wire, &owner, 5, 1, 302, b"\x03www\xc0\x0c");
    record(&mut wire, &owner, 2, 1, 303, b"\x02ns\xc0\x0c");
    record(&mut wire, &owner, 12, 1, 304, b"\x04mail\xc0\x0c");
    record(&mut wire, &owner, 15, 1, 305, b"\x00\x0a\x04mail\xc0\x0c");
    record(&mut wire, &owner, 16, 1, 306, b"\x00\x03abc\x02\x00\xff");
    let mut srv = vec![0, 10, 0, 20, 1, 187];
    srv.extend_from_slice(WWW);
    record(&mut wire, &owner, 33, 1, 307, &srv);
    record(
        &mut wire,
        &owner,
        257,
        1,
        308,
        b"\x80\x05issueletsencrypt.org",
    );
    record(&mut wire, &owner, 65280, 1, 309, b"\xff\xc0\x0c\x00\xfe");
    let mut soa = b"\x02ns\xc0\x0c\x0ahostmaster\xc0\x0c".to_vec();
    for field in [2026111001, 7200, 3600, 1209600, 300] {
        u32_into(&mut soa, field);
    }
    record(&mut wire, &owner, 6, 1, 3600, &soa);
    record(&mut wire, NS, 1, 1, 3600, &[192, 0, 2, 53]);
    record(
        &mut wire,
        &[0],
        41,
        1232,
        0x01008000,
        &[0, 10, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7],
    );
    wire
}

pub fn invalid_fixtures() -> Vec<Fixture> {
    let mut all = Vec::new();
    for (name, bytes) in [
        ("self-pointer", vec![0xc0, 12]),
        ("forward-pointer", vec![0xc0, 14, 0]),
        ("pointer-loop", vec![0xc0, 14, 0xc0, 12]),
        ("out-of-bounds", vec![0xff, 0xff]),
        ("truncated-pointer", vec![0xc0]),
        ("reserved-label", vec![0x80, 0]),
        ("truncated-label", vec![4, b'x']),
    ] {
        let mut wire = header(1, 0, 0, 0);
        wire.extend_from_slice(&bytes);
        all.push(Fixture { name, wire });
    }
    let mut long = header(1, 0, 0, 0);
    for _ in 0..4 {
        long.push(63);
        long.extend_from_slice(&[b'a'; 63]);
    }
    long.extend_from_slice(&[0, 0, 1, 0, 1]);
    all.push(Fixture {
        name: "overlong-name",
        wire: long,
    });
    all
}
