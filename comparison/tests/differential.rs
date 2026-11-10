use zdwire_comparison::{
    domain_raw, domain_snapshot, domain_specialized, domain_typed, encode, fixtures, zdwire_raw,
    zdwire_snapshot, zdwire_typed,
};

#[test]
fn every_supported_type_and_section_matches_domain() {
    for fixture in fixtures::valid_fixtures() {
        assert_eq!(
            zdwire_snapshot(&fixture.wire).unwrap(),
            domain_snapshot(&fixture.wire).unwrap(),
            "{}",
            fixture.name
        );
        assert_eq!(
            zdwire_typed(&fixture.wire).unwrap(),
            domain_specialized(&fixture.wire).unwrap(),
            "{}",
            fixture.name
        );
        assert_eq!(
            zdwire_raw(&fixture.wire).unwrap(),
            domain_raw(&fixture.wire).unwrap(),
            "{}",
            fixture.name
        );
        assert_eq!(
            zdwire_typed(&fixture.wire).unwrap(),
            domain_typed(&fixture.wire).unwrap(),
            "{}",
            fixture.name
        );
    }
}

#[test]
fn shared_invalid_compression_inputs_are_rejected() {
    for fixture in fixtures::invalid_fixtures() {
        assert!(zdwire_raw(&fixture.wire).is_err(), "{}", fixture.name);
        assert!(domain_raw(&fixture.wire).is_err(), "{}", fixture.name);
    }
}

#[test]
fn every_prefix_of_mixed_packet_agrees() {
    let fixture = fixtures::all_types();
    for len in 0..fixture.len() {
        assert!(
            zdwire_typed(&fixture[..len]).is_err(),
            "zdwire prefix={len}"
        );
        assert!(
            domain_typed(&fixture[..len]).is_err(),
            "domain prefix={len}"
        );
    }
}

#[test]
fn generated_binary_labels_and_responses_match() {
    let mut rng = 0x243f_6a88_85a3_08d3_u64;
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    for _ in 0..512 {
        let mut wire = vec![0; 12];
        wire[4..6].copy_from_slice(&1u16.to_be_bytes());
        wire[0..2].copy_from_slice(&(next() as u16).to_be_bytes());
        for _ in 0..3 {
            let len = (next() % 63 + 1) as usize;
            wire.push(len as u8);
            wire.extend((0..len).map(|_| next() as u8));
        }
        wire.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert_eq!(
            zdwire_snapshot(&wire).unwrap(),
            domain_snapshot(&wire).unwrap()
        );
        let count = (next() % 128) as u16;
        let mut response = fixtures::response(count, next() & 1 == 0);
        response[0..2].copy_from_slice(&(next() as u16).to_be_bytes());
        assert_eq!(
            zdwire_snapshot(&response).unwrap(),
            domain_snapshot(&response).unwrap()
        );
    }
}

#[test]
fn caller_buffer_encoding_is_byte_identical() {
    let mut zbuffer = vec![0; 65535];
    let mut dbuffer = vec![0; 65535];
    for case in encode::cases() {
        for compressed in [false, true] {
            let zlen = encode::zdwire(&case, &mut zbuffer, compressed);
            let dlen = encode::domain(&case, &mut dbuffer, compressed);
            assert_eq!(
                &zbuffer[..zlen],
                &dbuffer[..dlen],
                "{} compressed={compressed}",
                case.name
            );
            assert_eq!(
                zdwire_snapshot(&zbuffer[..zlen]).unwrap(),
                domain_snapshot(&dbuffer[..dlen]).unwrap(),
                "{}",
                case.name
            );
        }
    }
}

#[test]
fn ten_thousand_mutated_packets_agree_on_raw_wire_semantics() {
    let base = fixtures::all_types();
    let mut rng = 0x1319_8a2e_0370_7344_u64;
    for iteration in 0..10_000 {
        let mut wire = base.clone();
        for _ in 0..1 + iteration % 5 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let index = (rng as usize) % wire.len();
            wire[index] ^= (rng >> 32) as u8;
        }
        if iteration % 7 == 0 {
            wire.truncate((rng as usize) % wire.len());
        }
        assert_eq!(
            zdwire_raw(&wire).map_err(|_| zdwire_comparison::Rejected),
            domain_raw(&wire),
            "mutation={iteration}, input={wire:02x?}"
        );
    }
}

#[test]
fn caa_tags_use_the_full_rfc8659_length_range() {
    for tag_len in [1, 15, 16, 255] {
        let mut wire = vec![0; 12];
        wire[6..8].copy_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&[0, 1, 1, 0, 1, 0, 0, 0, 0]);
        wire.extend_from_slice(&((tag_len + 2) as u16).to_be_bytes());
        wire.extend_from_slice(&[0, tag_len as u8]);
        wire.extend(std::iter::repeat_n(b'a', tag_len));
        assert_eq!(
            zdwire_snapshot(&wire).unwrap(),
            domain_snapshot(&wire).unwrap(),
            "tag_len={tag_len}"
        );
    }
}

#[test]
fn stricter_pointer_budget_is_an_explicit_policy_difference() {
    let mut wire = vec![0; 12];
    wire[4..6].copy_from_slice(&34u16.to_be_bytes());
    let mut previous = 12;
    wire.extend_from_slice(&[0, 0, 1, 0, 1]);
    for _ in 0..33 {
        let offset = wire.len();
        wire.extend_from_slice(&(0xc000u16 | previous as u16).to_be_bytes());
        wire.extend_from_slice(&[0, 1, 0, 1]);
        previous = offset;
    }
    assert!(domain_raw(&wire).is_ok());
    assert_eq!(
        zdwire_raw(&wire).unwrap_err().kind,
        zdwire::ErrorKind::PointerLimit
    );
}

#[test]
fn empty_caa_tag_is_an_explicit_policy_difference() {
    let wire = [
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 2, 0, 0,
    ];
    assert!(domain_typed(&wire).is_ok());
    assert_eq!(
        zdwire_typed(&wire).unwrap_err().kind,
        zdwire::ErrorKind::InvalidRdata
    );
}

#[test]
fn every_rdata_type_round_trips_through_both_encoders() {
    let wire = fixtures::all_types();
    let expected = domain_snapshot(&wire).unwrap();
    let mut zbuffer = vec![0; 65535];
    let mut dbuffer = vec![0; 65535];
    for compressed in [false, true] {
        let zlen = encode::reencode_zdwire(&wire, &mut zbuffer, compressed);
        let dlen = encode::reencode_domain(&wire, &mut dbuffer, compressed);
        assert_eq!(zdwire_snapshot(&zbuffer[..zlen]).unwrap(), expected);
        assert_eq!(domain_snapshot(&zbuffer[..zlen]).unwrap(), expected);
        assert_eq!(zdwire_snapshot(&dbuffer[..dlen]).unwrap(), expected);
        assert_eq!(domain_snapshot(&dbuffer[..dlen]).unwrap(), expected);
        if !compressed {
            assert_eq!(&zbuffer[..zlen], &dbuffer[..dlen]);
        }
    }
}
