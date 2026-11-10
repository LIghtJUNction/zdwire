use zdwire::{
    encode_name, Class, Error, ErrorKind, Header, MessageBuilder, MessageView, Name, OptOptions,
    Rdata, RecordData, Section, Txt, Type,
};

const EXAMPLE: &[u8] = b"\x07example\x03com\0";

#[test]
fn rfc1035_section_4_1_4_compression_vector() {
    // RFC 1035 §4.1.4 uses these exact offsets and names.
    let mut wire = [0u8; 93];
    wire[20..32].copy_from_slice(b"\x01F\x03ISI\x04ARPA\0");
    wire[40..46].copy_from_slice(b"\x03FOO\xc0\x14");
    wire[64..66].copy_from_slice(b"\xc0\x1a");
    for (at, after, expected) in [
        (20, 32, "F.ISI.ARPA."),
        (40, 46, "FOO.F.ISI.ARPA."),
        (64, 66, "ARPA."),
        (92, 93, "."),
    ] {
        let (name, end) = Name::parse(&wire, at).unwrap();
        assert_eq!(end, after);
        assert_eq!(name.to_string(), expected);
        let mut expanded = [0; 255];
        let len = name.write_uncompressed(&mut expanded).unwrap();
        assert_eq!(name, Name::from_wire(&expanded[..len]).unwrap());
    }
}

#[test]
fn header_roundtrip_preserves_every_flag_and_maximum_count() {
    let header = Header {
        id: 0x1234,
        flags: 0xffff,
        questions: u16::MAX,
        answers: 0x1234,
        authorities: 0x5678,
        additionals: 0x9abc,
    };
    let mut bytes = [0; 12];
    assert_eq!(header.write(&mut bytes), Ok(12));
    assert_eq!(&bytes[..6], &[0x12, 0x34, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(Header::parse(&bytes), Ok(header));
    assert!(header.is_response());
    assert!(header.truncated());
    assert_eq!(header.opcode(), 15);
    assert_eq!(header.rcode(), 15);
    for len in 0..12 {
        assert_eq!(
            Header::parse(&bytes[..len]),
            Err(Error::new(ErrorKind::UnexpectedEnd, len))
        );
        let mut short = vec![0xaa; len];
        assert_eq!(
            header.write(&mut short),
            Err(Error::new(ErrorKind::BufferTooSmall { needed: 12 }, len))
        );
        assert!(short.iter().all(|b| *b == 0xaa));
    }
}

#[test]
fn all_sections_and_unknown_fields_are_preserved() {
    let name = Name::from_wire(EXAMPLE).unwrap();
    let mut out = [0; 512];
    let mut builder = MessageBuilder::new(&mut out, Header::new(99, 0xffff)).unwrap();
    builder
        .add_question(name, Type(65001), Class(65002))
        .unwrap();
    for (section, rr_type) in [
        (Section::Answer, 65001),
        (Section::Authority, 65002),
        (Section::Additional, 65003),
    ] {
        builder
            .add_record(
                section,
                name,
                Class(65004),
                u32::MAX,
                RecordData::Unknown {
                    rr_type: Type(rr_type),
                    rdata: &[0, 255, 0xc0, 12],
                },
            )
            .unwrap();
    }
    let view = MessageView::parse_strict(builder.as_bytes()).unwrap();
    let question = view.questions().next().unwrap().unwrap();
    assert_eq!(question.qtype, Type(65001));
    assert_eq!(question.qclass, Class(65002));
    assert_eq!(view.header().flags, 0xffff);
    for (records, expected) in [
        (view.answers().unwrap(), Section::Answer),
        (view.authorities().unwrap(), Section::Authority),
        (view.additionals().unwrap(), Section::Additional),
    ] {
        let records: Vec<_> = records.map(Result::unwrap).collect();
        assert_eq!(records.len(), 1);
        let record = records[0];
        assert_eq!(record.section, expected);
        assert_eq!(record.class, Class(65004));
        assert_eq!(record.ttl, u32::MAX);
        assert!(matches!(
            record.data().unwrap(),
            Rdata::Unknown {
                rdata: [0, 255, 0xc0, 12],
                ..
            }
        ));
    }
}

#[test]
fn lazy_and_strict_validation_are_explicit() {
    let mut bytes = [0u8; 13];
    bytes[12] = 99;
    let view = MessageView::parse(&bytes).unwrap();
    assert_eq!(
        view.validate(),
        Err(Error::new(ErrorKind::TrailingData, 12))
    );
    bytes[5] = 1;
    let view = MessageView::parse(&bytes[..12]).unwrap();
    assert_eq!(
        view.validate(),
        Err(Error::new(ErrorKind::UnexpectedEnd, 12))
    );
    let mut questions = view.questions();
    assert!(questions.next().unwrap().is_err());
    assert!(questions.next().is_none());
    let mut records = view.records();
    assert!(records.next().unwrap().is_err());
    assert!(records.next().is_none());
}

fn one_record(rr_type: Type, rdata: &[u8], section: Section) -> Vec<u8> {
    let mut header = Header::new(1, Header::QR);
    match section {
        Section::Answer => header.answers = 1,
        Section::Authority => header.authorities = 1,
        Section::Additional => header.additionals = 1,
    }
    let mut wire = vec![0; 12];
    header.write(&mut wire).unwrap();
    wire.push(0);
    wire.extend(rr_type.0.to_be_bytes());
    wire.extend(1u16.to_be_bytes());
    wire.extend(0u32.to_be_bytes());
    wire.extend((rdata.len() as u16).to_be_bytes());
    wire.extend(rdata);
    wire
}

#[test]
fn malformed_typed_data_keeps_absolute_error_offsets() {
    for (kind, data) in [
        (Type::A, &[1, 2, 3][..]),
        (Type::AAAA, &[0][..]),
        (Type::TXT, &[][..]),
        (Type::SOA, &[0, 0][..]),
        (Type::CAA, &[0, 0][..]),
    ] {
        let wire = one_record(kind, data, Section::Answer);
        let record = MessageView::parse(&wire)
            .unwrap()
            .records()
            .next()
            .unwrap()
            .unwrap();
        let error = record.data().unwrap_err();
        assert!(error.offset >= record.rdata_offset());
        assert!(error.offset <= wire.len());
    }
    let wire = one_record(Type::TXT, b"\x05abcd", Section::Answer);
    assert_eq!(
        MessageView::parse(&wire).unwrap().validate(),
        Err(Error::new(ErrorKind::UnexpectedEnd, wire.len()))
    );
    let wire = one_record(Type::CNAME, b"\x03ab", Section::Answer);
    assert_eq!(
        MessageView::parse(&wire).unwrap().validate(),
        Err(Error::new(ErrorKind::UnexpectedEnd, wire.len()))
    );
}

#[test]
fn names_cannot_consume_the_following_record_to_complete_rdata() {
    let mut wire = one_record(Type::CNAME, b"\x01a", Section::Answer);
    wire[7] = 2;
    // This next record begins with a zero that must not terminate the CNAME.
    wire.extend_from_slice(&one_record(Type(65000), &[], Section::Answer)[12..]);
    let view = MessageView::parse(&wire).unwrap();
    assert_eq!(
        view.validate(),
        Err(Error::new(ErrorKind::UnexpectedEnd, 25))
    );
}

#[test]
fn srv_target_compression_is_rejected_but_raw_bytes_are_available() {
    let wire = one_record(Type::SRV, &[0, 1, 0, 2, 0, 80, 0xc0, 12], Section::Answer);
    let record = MessageView::parse(&wire)
        .unwrap()
        .records()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(record.rdata.len(), 8);
    assert_eq!(
        record.data().unwrap_err(),
        Error::new(ErrorKind::InvalidRdata, 29)
    );
}

#[test]
fn edns_option_values_and_extended_rcode_round_trip() {
    let mut out = [0; 512];
    let mut writer = MessageBuilder::new(&mut out, Header::new(1, 3)).unwrap();
    writer
        .add_opt(4096, 0xab, 2, 0x8001, &[0, 8, 0, 0, 0xfd, 0xe9, 0, 2, 7, 8])
        .unwrap();
    let view = MessageView::parse_strict(writer.as_bytes()).unwrap();
    let record = view.records().next().unwrap().unwrap();
    let Rdata::Opt(opt) = record.data().unwrap() else {
        panic!("wrong type")
    };
    assert_eq!(opt.udp_payload_size(), 4096);
    assert_eq!(opt.version(), 2);
    assert_eq!(opt.extended_rcode(), 0xab);
    assert_eq!(opt.flags(), 0x8001);
    assert!(opt.dnssec_ok());
    assert_eq!(opt.full_rcode(view.header().rcode()), 0xab3);
    let items: Vec<_> = opt.options().collect();
    assert_eq!(items[0].code, 8);
    assert_eq!(items[0].data, &[]);
    assert_eq!(items[1].code, 65001);
    assert_eq!(items[1].data, &[7, 8]);
}

#[test]
fn opt_placement_owner_uniqueness_and_truncation_are_checked() {
    let wire = one_record(Type::OPT, &[], Section::Answer);
    assert_eq!(
        MessageView::parse(&wire)
            .unwrap()
            .validate()
            .unwrap_err()
            .kind,
        ErrorKind::InvalidOpt
    );
    let mut wire = one_record(Type::OPT, &[], Section::Additional);
    wire[11] = 2;
    wire.extend_from_slice(&one_record(Type::OPT, &[], Section::Additional)[12..]);
    assert_eq!(
        MessageView::parse(&wire)
            .unwrap()
            .validate()
            .unwrap_err()
            .kind,
        ErrorKind::DuplicateOpt
    );
    let mut wire = one_record(Type::OPT, &[], Section::Additional);
    wire.splice(12..13, [0xc0, 0]);
    assert_eq!(
        MessageView::parse(&wire)
            .unwrap()
            .validate()
            .unwrap_err()
            .kind,
        ErrorKind::InvalidOpt
    );
    for data in [&[0][..], &[0, 1, 0][..], &[0, 1, 0, 1][..]] {
        let wire = one_record(Type::OPT, data, Section::Additional);
        assert_eq!(
            MessageView::parse(&wire)
                .unwrap()
                .validate()
                .unwrap_err()
                .kind,
            ErrorKind::InvalidOpt
        );
        assert!(OptOptions::parse(data).is_err());
    }
}

#[test]
fn txt_empty_string_binary_data_and_string_boundaries() {
    assert!(Txt::parse(&[]).is_err());
    let txt = Txt::parse(b"\0\x03a\0b\x01\xff").unwrap();
    assert_eq!(
        txt.iter().collect::<Vec<_>>(),
        vec![&[][..], &b"a\0b"[..], &[255][..]]
    );
    let mut iter = txt.iter();
    for _ in 0..3 {
        assert!(iter.next().is_some());
    }
    assert!(iter.next().is_none());
    assert!(iter.next().is_none());
}

#[test]
fn text_names_escape_and_roundtrip_every_octet() {
    for byte in 0..=255u8 {
        let wire = [1, byte, 0];
        let name = Name::from_wire(&wire).unwrap();
        let mut out = [0; 255];
        let len = encode_name(&name.to_string(), &mut out).unwrap();
        assert_eq!(&out[..len], &wire);
    }
    for text in ["example.com", "example.com."] {
        let mut out = [0; 255];
        let len = encode_name(text, &mut out).unwrap();
        assert_eq!(&out[..len], EXAMPLE);
    }
    for text in ["", "."] {
        assert_eq!(encode_name(text, &mut [0; 1]), Ok(1));
    }
    for text in ["a..b", "..", "a\\", "a\\0", "a\\01", "a\\256", "a\\12x"] {
        let mut out = [0x55; 255];
        assert!(encode_name(text, &mut out).is_err(), "{text}");
        assert_eq!(out, [0x55; 255]);
    }
}

#[test]
fn label_length_name_length_and_exact_capacity_boundaries() {
    let labels = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ];
    let text = labels.join(".");
    let mut out = [0; 255];
    assert_eq!(encode_name(&text, &mut out), Ok(255));
    let name = Name::from_wire(&out).unwrap();
    assert_eq!(name.wire_len(), 255);
    assert_eq!(name.labels().count(), 4);
    let mut short = [0xa5; 254];
    assert_eq!(
        name.write_uncompressed(&mut short),
        Err(Error::new(ErrorKind::BufferTooSmall { needed: 255 }, 254))
    );
    assert_eq!(short, [0xa5; 254]);
    assert_eq!(
        encode_name(&(text.clone() + "d"), &mut out)
            .unwrap_err()
            .kind,
        ErrorKind::NameTooLong
    );
    assert_eq!(
        encode_name(&"a".repeat(64), &mut out).unwrap_err().kind,
        ErrorKind::LabelTooLong
    );
}

#[test]
fn dns_case_folding_and_display_preserve_octets() {
    let lower = Name::from_wire(b"\x03foo\0").unwrap();
    let upper = Name::from_wire(b"\x03FoO\0").unwrap();
    assert_eq!(lower, upper);
    assert!(!lower.eq_case_sensitive(upper));
    assert_eq!(upper.to_string(), "FoO.");
    assert_ne!(
        Name::from_wire(&[1, 0xc0, 0]).unwrap(),
        Name::from_wire(&[1, 0xe0, 0]).unwrap()
    );
}

#[test]
fn replacing_public_rdata_does_not_forge_a_compression_context() {
    let wire = one_record(Type::A, &[1, 2, 3, 4], Section::Answer);
    let mut record = MessageView::parse(&wire)
        .unwrap()
        .records()
        .next()
        .unwrap()
        .unwrap();
    record.rdata = &[8, 8, 8, 8];
    assert_eq!(record.data().unwrap_err().kind, ErrorKind::InvalidRdata);
}

#[test]
fn standalone_rdata_respects_the_wire_length_limit() {
    let bytes = vec![0u8; 65_536];
    assert!(Txt::parse(&bytes[..65_535]).is_ok());
    assert_eq!(
        Txt::parse(&bytes).unwrap_err(),
        Error::new(ErrorKind::InvalidRdata, 65_535)
    );
    assert!(OptOptions::parse(&bytes[..65_532]).is_ok());
    assert_eq!(
        OptOptions::parse(&bytes).unwrap_err(),
        Error::new(ErrorKind::InvalidOpt, 65_535)
    );
}
