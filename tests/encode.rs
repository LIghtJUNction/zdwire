use zdwire::{
    Class, CompressionEntry, ErrorKind, Header, MessageBuilder, MessageView, Name, RecordData,
    Section, Type,
};

const EXAMPLE: &[u8] = b"\x07example\x03com\0";
const WWW: &[u8] = b"\x03www\x07example\x03com\0";
const NS: &[u8] = b"\x02ns\x07example\x03com\0";
const MAILBOX: &[u8] = b"\x0ahostmaster\x07example\x03com\0";

fn name(wire: &[u8]) -> Name<'_> {
    Name::from_wire(wire).unwrap()
}

fn u16_at(wire: &[u8], pos: usize) -> u16 {
    u16::from_be_bytes([wire[pos], wire[pos + 1]])
}

#[test]
fn query_matches_standard_wire_layout() {
    let mut output = [0xa5; 64];
    let mut encoder = MessageBuilder::new(&mut output, Header::new(0x1234, 0x0100)).unwrap();
    encoder.add_question(name(WWW), Type::A, Class::IN).unwrap();
    assert_eq!(encoder.len(), 33);
    assert!(!encoder.is_empty());
    let wire = encoder.finish();
    assert_eq!(&wire[..12], &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&wire[12..29], WWW);
    assert_eq!(&wire[29..], &[0, 1, 0, 1]);
    MessageView::parse(wire).unwrap().validate().unwrap();
    assert!(output[33..].iter().all(|byte| *byte == 0xa5));
}

#[test]
fn compression_preserves_names_and_uses_prior_label_boundaries() {
    let mut output = [0; 512];
    let mut table = [CompressionEntry::EMPTY; 256];
    let mut encoder =
        MessageBuilder::with_compression(&mut output, Header::new(7, 0x8180), &mut table).unwrap();
    encoder.add_question(name(WWW), Type::A, Class::IN).unwrap();
    let first_answer = encoder.len();
    encoder
        .add_record(
            Section::Answer,
            name(WWW),
            Class::IN,
            3600,
            RecordData::A([192, 0, 2, 1]),
        )
        .unwrap();
    let authority = encoder.len();
    encoder
        .add_record(
            Section::Authority,
            name(EXAMPLE),
            Class::IN,
            60,
            RecordData::Ns(name(NS)),
        )
        .unwrap();
    let wire = encoder.finish();
    assert_eq!(&wire[first_answer..first_answer + 2], &[0xc0, 0x0c]);
    assert_eq!(&wire[authority..authority + 2], &[0xc0, 0x10]);
    assert_eq!(u16_at(wire, 6), 1);
    assert_eq!(u16_at(wire, 8), 1);
    let (decoded, _) = Name::parse(wire, authority).unwrap();
    let mut flat = [0; 255];
    let len = decoded.write_uncompressed(&mut flat).unwrap();
    assert_eq!(&flat[..len], EXAMPLE);
    MessageView::parse(wire).unwrap().validate().unwrap();
}

#[test]
fn all_supported_records_and_unknown_data_round_trip() {
    for compressed in [false, true] {
        let mut output = [0; 2048];
        let mut table = [CompressionEntry::EMPTY; 256];
        let mut encoder = if compressed {
            MessageBuilder::with_compression(&mut output, Header::new(12, 0x8180), &mut table)
                .unwrap()
        } else {
            MessageBuilder::new(&mut output, Header::new(12, 0x8180)).unwrap()
        };
        encoder
            .add_question(name(EXAMPLE), Type::A, Class::IN)
            .unwrap();
        let records = [
            RecordData::A([192, 0, 2, 8]),
            RecordData::Aaaa([0x20; 16]),
            RecordData::Ns(name(NS)),
            RecordData::Cname(name(WWW)),
            RecordData::Ptr(name(EXAMPLE)),
            RecordData::Mx {
                preference: 10,
                exchange: name(NS),
            },
            RecordData::Txt(b"\x03one\x03two\x00"),
            RecordData::Soa {
                mname: name(NS),
                rname: name(MAILBOX),
                serial: 0xf123_4567,
                refresh: 7200,
                retry: 60,
                expire: 86400,
                minimum: 1800,
            },
            RecordData::Srv {
                priority: 1,
                weight: 50,
                port: 443,
                target: name(WWW),
            },
            RecordData::Caa {
                flags: 128,
                tag: b"issue",
                value: b"ca.example",
            },
            RecordData::Unknown {
                rr_type: Type(65000),
                rdata: &[0xc0, 0x0c, 0, 255],
            },
        ];
        for record in records {
            encoder
                .add_record(Section::Answer, name(EXAMPLE), Class::IN, 123, record)
                .unwrap();
        }
        encoder
            .add_opt(1232, 1, 0, 0x8000, &[0, 12, 0, 3, 0, 0, 0])
            .unwrap();
        let wire = encoder.finish();
        assert_eq!(u16_at(wire, 6), 11);
        assert_eq!(u16_at(wire, 10), 1);
        MessageView::parse(wire).unwrap().validate().unwrap();

        let mut pos = 12;
        let (_, end) = Name::parse(wire, pos).unwrap();
        pos = end + 4;
        for record in records {
            let (_, fields) = Name::parse(wire, pos).unwrap();
            assert_eq!(u16_at(wire, fields), record.rr_type().0);
            let data = fields + 10;
            let end = data + u16_at(wire, fields + 8) as usize;
            match record {
                RecordData::A(value) => assert_eq!(&wire[data..end], &value),
                RecordData::Aaaa(value) => assert_eq!(&wire[data..end], &value),
                RecordData::Txt(value) => assert_eq!(&wire[data..end], value),
                RecordData::Unknown { rdata, .. } => assert_eq!(&wire[data..end], rdata),
                RecordData::Srv { .. } => assert_eq!(wire[data + 6], 3),
                RecordData::Caa { .. } => assert_eq!(&wire[data..data + 7], b"\x80\x05issue"),
                _ => {}
            }
            pos = end;
        }
        assert_eq!(wire[pos], 0);
        assert_eq!(u16_at(wire, pos + 1), 41);
        assert_eq!(u16_at(wire, pos + 3), 1232);
        assert_eq!(&wire[pos + 5..pos + 9], &[1, 0, 0x80, 0]);
    }
}

#[test]
fn capacity_errors_are_exact_and_leave_all_output_bytes_untouched() {
    for capacity in 12..33 {
        let mut output = vec![0xa5; capacity];
        let error;
        {
            let mut encoder = MessageBuilder::new(&mut output, Header::new(7, 0)).unwrap();
            error = encoder
                .add_question(name(WWW), Type::AAAA, Class::IN)
                .unwrap_err();
            assert_eq!(encoder.len(), 12);
            assert_eq!(encoder.as_bytes(), &[0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        }
        assert_eq!(error.kind, ErrorKind::BufferTooSmall { needed: 33 });
        assert_eq!(error.offset, capacity);
        assert!(output[12..].iter().all(|byte| *byte == 0xa5));
    }
    for capacity in 0..12 {
        let mut output = vec![0xa5; capacity];
        let error = match MessageBuilder::new(&mut output, Header::new(0, 0)) {
            Ok(_) => panic!("short header buffer unexpectedly accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::BufferTooSmall { needed: 12 });
        assert!(output.iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn failed_record_keeps_section_counts_dictionary_and_content() {
    let mut failed_output = [0xa5; 64];
    let mut clean_output = [0xa5; 64];
    let mut failed_table = [CompressionEntry::EMPTY; 32];
    let mut clean_table = [CompressionEntry::EMPTY; 32];
    let header = Header::new(11, 0x8180);
    let mut failed =
        MessageBuilder::with_compression(&mut failed_output, header, &mut failed_table).unwrap();
    let mut clean =
        MessageBuilder::with_compression(&mut clean_output, header, &mut clean_table).unwrap();
    for encoder in [&mut failed, &mut clean] {
        encoder
            .add_question(name(EXAMPLE), Type::A, Class::IN)
            .unwrap();
    }
    let before = failed.as_bytes().to_vec();
    let error = failed
        .add_record(
            Section::Additional,
            name(MAILBOX),
            Class::IN,
            0,
            RecordData::Aaaa([7; 16]),
        )
        .unwrap_err();
    assert!(matches!(error.kind, ErrorKind::BufferTooSmall { .. }));
    assert_eq!(failed.as_bytes(), &before);
    for encoder in [&mut failed, &mut clean] {
        encoder
            .add_record(
                Section::Answer,
                name(EXAMPLE),
                Class::IN,
                0,
                RecordData::A([1, 2, 3, 4]),
            )
            .unwrap();
    }
    assert_eq!(failed.finish(), clean.finish());
    assert_eq!(failed_output, clean_output);
}

#[test]
fn validation_errors_are_transactional() {
    let mut output = [0; 512];
    let mut encoder = MessageBuilder::new(&mut output, Header::new(0, 0)).unwrap();
    let oversized_tag = [b'a'; 256];
    let invalid = [
        RecordData::Txt(b""),
        RecordData::Txt(b"\x02a"),
        RecordData::Caa {
            flags: 0,
            tag: b"",
            value: b"",
        },
        RecordData::Caa {
            flags: 0,
            tag: b"issue-wild",
            value: b"ca.example",
        },
        RecordData::Caa {
            flags: 0,
            tag: &oversized_tag,
            value: b"",
        },
        RecordData::Unknown {
            rr_type: Type::A,
            rdata: &[1, 2, 3, 4],
        },
        RecordData::Unknown {
            rr_type: Type::OPT,
            rdata: b"",
        },
    ];
    for record in invalid {
        let error = encoder
            .add_record(Section::Additional, name(EXAMPLE), Class::IN, 0, record)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidRdata);
        assert_eq!(encoder.len(), 12);
    }
    for wire in [&[0][..], &[0, 1, 0, 2, 7][..]] {
        assert_eq!(
            encoder.add_opt(1232, 0, 0, 0, wire).unwrap_err().kind,
            ErrorKind::InvalidOpt
        );
        assert_eq!(encoder.len(), 12);
    }
    encoder
        .add_question(name(EXAMPLE), Type::A, Class::IN)
        .unwrap();
    encoder.add_opt(1232, 0, 0, 0, &[]).unwrap();
    let before = encoder.as_bytes().to_vec();
    assert_eq!(
        encoder.add_opt(1232, 0, 0, 0, &[]).unwrap_err().kind,
        ErrorKind::DuplicateOpt
    );
    assert_eq!(
        encoder
            .add_question(name(EXAMPLE), Type::A, Class::IN)
            .unwrap_err()
            .kind,
        ErrorKind::InvalidSection
    );
    assert_eq!(
        encoder
            .add_record(
                Section::Answer,
                name(EXAMPLE),
                Class::IN,
                0,
                RecordData::A([0; 4])
            )
            .unwrap_err()
            .kind,
        ErrorKind::InvalidSection
    );
    assert_eq!(encoder.as_bytes(), &before);
}

#[test]
fn message_size_limit_is_exact() {
    let data = vec![0x55; 65_512];
    let mut output = vec![0; 65_536];
    let mut encoder = MessageBuilder::new(&mut output, Header::new(0, 0)).unwrap();
    encoder
        .add_record(
            Section::Answer,
            name(&[0]),
            Class::IN,
            0,
            RecordData::Unknown {
                rr_type: Type(65000),
                rdata: &data,
            },
        )
        .unwrap();
    assert_eq!(encoder.len(), 65_535);
    assert_eq!(
        encoder.add_opt(1232, 0, 0, 0, &[]).unwrap_err().kind,
        ErrorKind::MessageTooLong
    );
    MessageView::parse(encoder.finish())
        .unwrap()
        .validate()
        .unwrap();
}

#[test]
fn compression_never_truncates_offsets_beyond_fourteen_bits() {
    let data = vec![0; 16_384];
    let mut output = vec![0; 20_000];
    let mut table = [CompressionEntry::EMPTY; 32];
    let mut encoder =
        MessageBuilder::with_compression(&mut output, Header::new(0, 0), &mut table).unwrap();
    encoder
        .add_record(
            Section::Answer,
            name(&[0]),
            Class::IN,
            0,
            RecordData::Unknown {
                rr_type: Type(65000),
                rdata: &data,
            },
        )
        .unwrap();
    for _ in 0..2 {
        let start = encoder.len();
        encoder
            .add_record(
                Section::Answer,
                name(EXAMPLE),
                Class::IN,
                0,
                RecordData::A([0; 4]),
            )
            .unwrap();
        assert_eq!(&encoder.as_bytes()[start..start + EXAMPLE.len()], EXAMPLE);
    }
    MessageView::parse(encoder.finish())
        .unwrap()
        .validate()
        .unwrap();
}

#[test]
fn dictionary_collisions_change_size_only() {
    for slots in [0, 1, 2, 3, 16, 256] {
        let mut table = vec![CompressionEntry::EMPTY; slots];
        let mut output = [0; 2048];
        let mut encoder =
            MessageBuilder::with_compression(&mut output, Header::new(0, 0), &mut table).unwrap();
        for wire in [WWW, EXAMPLE, NS, MAILBOX, WWW, NS, EXAMPLE, MAILBOX] {
            encoder
                .add_question(name(wire), Type::A, Class::IN)
                .unwrap();
        }
        let bytes = encoder.finish();
        let mut offset = 12;
        for wire in [WWW, EXAMPLE, NS, MAILBOX, WWW, NS, EXAMPLE, MAILBOX] {
            let (decoded, end) = Name::parse(bytes, offset).unwrap();
            let mut flat = [0; 255];
            let len = decoded.write_uncompressed(&mut flat).unwrap();
            assert_eq!(&flat[..len], wire);
            offset = end + 4;
        }
        assert_eq!(offset, bytes.len());
        MessageView::parse(bytes).unwrap().validate().unwrap();
    }
}

#[test]
fn header_counts_are_owned_by_builder() {
    let header = Header {
        id: 3,
        flags: 0x8180,
        questions: 5,
        answers: 6,
        authorities: 7,
        additionals: 8,
    };
    let mut output = [0; 12];
    let encoder = MessageBuilder::new(&mut output, header).unwrap();
    assert_eq!(&encoder.as_bytes()[4..], &[0; 8]);
}

#[test]
fn parsed_compressed_names_reencode_without_source_pointer_relocation() {
    let source = b"\x07example\x03com\0\x03www\xc0\x00\x04mail\xc0\x00";
    let (www, next) = Name::parse(source, EXAMPLE.len()).unwrap();
    let (mail, _) = Name::parse(source, next).unwrap();
    for compressed in [false, true] {
        let mut output = [0; 256];
        let mut table = [CompressionEntry::EMPTY; 256];
        let mut encoder = if compressed {
            MessageBuilder::with_compression(&mut output, Header::new(0, 0), &mut table).unwrap()
        } else {
            MessageBuilder::new(&mut output, Header::new(0, 0)).unwrap()
        };
        encoder.add_question(www, Type::A, Class::IN).unwrap();
        encoder.add_question(mail, Type::A, Class::IN).unwrap();
        encoder.add_question(www, Type::A, Class::IN).unwrap();
        let wire = encoder.finish();
        let mut offset = 12;
        for original in [www, mail, www] {
            let (actual, end) = Name::parse(wire, offset).unwrap();
            assert!(actual.eq_case_sensitive(original));
            offset = end + 4;
        }
        assert_eq!(offset, wire.len());
        MessageView::parse(wire).unwrap().validate().unwrap();
    }
}

#[test]
fn caa_tag_uses_the_entire_nonzero_single_octet_length_range() {
    for size in [1, 15, 16, 254, 255] {
        let mut output = [0; 512];
        let tag = vec![b'x'; size];
        let mut encoder = MessageBuilder::new(&mut output, Header::new(0, 0)).unwrap();
        encoder
            .add_record(
                Section::Answer,
                name(&[0]),
                Class::IN,
                0,
                RecordData::Caa {
                    flags: 0,
                    tag: &tag,
                    value: &[],
                },
            )
            .unwrap();
        let wire = encoder.finish();
        assert_eq!(wire[24] as usize, size);
        MessageView::parse(wire).unwrap().validate().unwrap();
    }
}

#[test]
fn oversized_opt_length_cannot_overflow_on_narrow_targets() {
    let mut output = [0; 64];
    let mut encoder = MessageBuilder::new(&mut output, Header::new(0, 0)).unwrap();
    assert_eq!(
        encoder
            .add_opt(1232, 0, 0, 0, &[0, 1, 255, 255])
            .unwrap_err()
            .kind,
        ErrorKind::InvalidOpt
    );
    assert_eq!(encoder.len(), 12);
}
