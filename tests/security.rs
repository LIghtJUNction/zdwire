use zdwire::{ErrorKind, MAX_POINTER_HOPS, MessageView, Name};

#[test]
fn pointers_reject_self_forward_cycles_and_out_of_bounds() {
    let error = Name::parse(&[0xc0, 0], 0).unwrap_err();
    assert_eq!((error.kind, error.offset), (ErrorKind::PointerLoop, 0));
    let error = Name::parse(&[0xc0, 2, 0xc0, 0], 0).unwrap_err();
    assert_eq!((error.kind, error.offset), (ErrorKind::ForwardPointer, 0));
    let error = Name::parse(&[0xc0, 9], 0).unwrap_err();
    assert_eq!(
        (error.kind, error.offset),
        (ErrorKind::PointerOutOfBounds, 0)
    );
    // A backward pointer can cycle through a preceding literal label.
    let error = Name::parse(&[1, b'a', 0xc0, 0], 2).unwrap_err();
    assert_eq!(error.kind, ErrorKind::PointerLoop);
}

#[test]
fn pointer_hop_budget_is_exact() {
    let mut wire = vec![0];
    let mut offset = 0;
    for _ in 0..MAX_POINTER_HOPS {
        let next = wire.len();
        wire.extend_from_slice(&[0xc0 | ((offset >> 8) as u8), offset as u8]);
        offset = next;
    }
    assert!(Name::parse(&wire, offset).unwrap().0.is_root());
    let next = wire.len();
    wire.extend_from_slice(&[0xc0 | ((offset >> 8) as u8), offset as u8]);
    assert_eq!(
        Name::parse(&wire, next).unwrap_err().kind,
        ErrorKind::PointerLimit
    );
}

#[test]
fn every_truncated_query_is_rejected_by_full_validation() {
    let wire = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01";
    assert!(MessageView::parse(wire).unwrap().validate().is_ok());
    for end in 0..wire.len() {
        assert!(
            MessageView::parse(&wire[..end])
                .and_then(|view| view.validate())
                .is_err()
        );
    }
}

#[test]
fn names_enforce_length_and_integer_boundaries() {
    assert_eq!(
        Name::parse(&[0], usize::MAX).unwrap_err().kind,
        ErrorKind::UnexpectedEnd
    );
    assert_eq!(
        Name::parse(&[0xc0], 0).unwrap_err().kind,
        ErrorKind::UnexpectedEnd
    );
    for tag in [0x40, 0x80, 0xbf] {
        assert_eq!(
            Name::parse(&[tag, 0], 0).unwrap_err().kind,
            ErrorKind::InvalidLabelType
        );
    }
    let mut wire = Vec::new();
    for _ in 0..4 {
        wire.push(63);
        wire.extend_from_slice(&[b'x'; 63]);
    }
    wire.push(0);
    assert_eq!(
        Name::parse(&wire, 0).unwrap_err().kind,
        ErrorKind::NameTooLong
    );
    assert_eq!(
        MessageView::parse(&vec![0; 65_536]).unwrap_err().kind,
        ErrorKind::MessageTooLong
    );
}

#[test]
fn all_two_byte_names_terminate() {
    // Miri covers each tag class; native tests exhaust all 65,536 combinations.
    let stride = if cfg!(miri) { 17 } else { 1 };
    for first in (0u16..256).step_by(stride) {
        for second in (0u16..256).step_by(stride) {
            if let Ok((name, _)) = Name::parse(&[first as u8, second as u8], 0) {
                assert!(name.labels().count() <= 127);
            }
        }
    }
}

#[test]
fn random_messages_and_offsets_do_not_panic() {
    let rounds = if cfg!(miri) { 64 } else { 10_000 };
    let mut state = 0x45ae_f190_abcd_1234u64;
    for round in 0..rounds {
        let length = round % 513;
        let mut bytes = vec![0; length];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        let _ = Name::parse(&bytes, length / 2);
        let _ = Name::parse(&bytes, usize::MAX);
        if let Ok(view) = MessageView::parse(&bytes) {
            let _ = view.validate();
            let mut count = 0;
            for question in view.questions() {
                count += 1;
                assert!(count <= 65_536);
                if let Ok(question) = question {
                    assert!(question.name.labels().count() <= 127);
                }
            }
            count = 0;
            for record in view.records() {
                count += 1;
                assert!(count <= 196_606);
                if let Ok(record) = record {
                    let _ = record.data();
                    assert!(record.name.labels().count() <= 127);
                }
            }
        }
    }
}

#[test]
fn malformed_encoding_is_transactional() {
    use zdwire::{Class, CompressionEntry, Header, MessageBuilder, RecordData, Section, Type};
    let mut output = [0xa5; 128];
    let mut table = [CompressionEntry::EMPTY; 8];
    let name = Name::from_wire(b"\x01a\x00").unwrap();
    let mut builder =
        MessageBuilder::with_compression(&mut output, Header::default(), &mut table).unwrap();
    builder.add_question(name, Type::A, Class::IN).unwrap();
    let before = builder.as_bytes().to_vec();
    for data in [
        RecordData::Txt(&[255, 1]),
        RecordData::Caa {
            flags: 0,
            tag: b"bad!",
            value: b"",
        },
        RecordData::Unknown {
            rr_type: Type::A,
            rdata: &[1, 2, 3, 4],
        },
    ] {
        assert!(
            builder
                .add_record(Section::Answer, name, Class::IN, 0, data)
                .is_err()
        );
        assert_eq!(builder.as_bytes(), before);
    }
    for options in [&[0u8, 1, 0xff, 0xff][..], &[0u8][..], &[0, 1, 0, 2, 0][..]] {
        assert!(builder.add_opt(1232, 0, 0, 0, options).is_err());
        assert_eq!(builder.as_bytes(), before);
    }
    builder
        .add_record(
            Section::Answer,
            name,
            Class::IN,
            0,
            RecordData::A([192, 0, 2, 1]),
        )
        .unwrap();
    builder.add_opt(1232, 0, 0, 0, &[]).unwrap();
    MessageView::parse(builder.as_bytes())
        .unwrap()
        .validate()
        .unwrap();
}

#[test]
fn changed_record_fields_cannot_break_private_bounds() {
    use zdwire::Type;
    let packet = b"\0\0\x81\x80\0\0\0\x01\0\0\0\0\0\0\x01\0\x01\0\0\0\x3c\0\x04\xc0\0\x02\x01";
    let record = MessageView::parse(packet)
        .unwrap()
        .records()
        .next()
        .unwrap()
        .unwrap();
    for length in 0..=record.rdata.len() {
        for rr_type in [
            Type::A,
            Type::AAAA,
            Type::NS,
            Type::CNAME,
            Type::PTR,
            Type::SOA,
            Type::MX,
            Type::TXT,
            Type::SRV,
            Type::CAA,
            Type::OPT,
        ] {
            let mut edited = record;
            edited.rr_type = rr_type;
            edited.rdata = &record.rdata[..length];
            let _ = edited.data();
        }
    }
    let mut edited = record;
    edited.rdata = b"\xc0\x00\x02\x01";
    assert_eq!(edited.data().unwrap_err().kind, ErrorKind::InvalidRdata);
}

#[test]
fn contiguous_name_spans_preserve_pointer_and_literal_semantics() {
    let chained = b"\x01a\x00\xc0\x00\xc0\x03";
    for offset in [0, 3, 5] {
        let name = Name::parse(chained, offset).unwrap().0;
        let plain = name.as_uncompressed().unwrap();
        assert_eq!(plain, b"\x01a\x00");
        assert_eq!(plain.as_ptr(), chained.as_ptr());
        assert_eq!(name.wire_len(), 3);
        let mut output = [0xa5; 8];
        assert_eq!(name.write_uncompressed(&mut output).unwrap(), 3);
        assert_eq!(&output[..3], plain);
        assert_eq!(&output[3..], &[0xa5; 5]);
    }
    // The final pointer targets a name containing literals followed by a pointer.
    let mixed = b"\x01a\x00\x01b\xc0\x00\xc0\x03";
    for offset in [3, 7] {
        let name = Name::parse(mixed, offset).unwrap().0;
        assert!(name.as_uncompressed().is_none());
        assert_eq!(name.wire_len(), 5);
        for capacity in [0, 4] {
            let mut output = [0xa5; 8];
            let error = name
                .write_uncompressed(&mut output[..capacity])
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::BufferTooSmall { needed: 5 });
            assert_eq!(error.offset, capacity);
            assert_eq!(output, [0xa5; 8]);
        }
        let mut output = [0xa5; 8];
        assert_eq!(name.write_uncompressed(&mut output).unwrap(), 5);
        assert_eq!(&output[..5], b"\x01b\x01a\x00");
        assert_eq!(&output[5..], &[0xa5; 3]);
    }
    let root_chain = b"\0\xc0\0\xc0\x01";
    let root = Name::parse(root_chain, 3).unwrap().0;
    assert!(root.is_root());
    assert_eq!(root.as_uncompressed(), Some(&root_chain[..1]));
}

#[test]
fn longest_contiguous_name_keeps_metadata_out_of_wire_length() {
    let mut packet = Vec::new();
    for length in [63, 63, 63, 61] {
        packet.push(length);
        packet.extend(std::iter::repeat(b'x').take(length as usize));
    }
    packet.push(0);
    assert_eq!(packet.len(), 255);
    packet.extend_from_slice(&[0xc0, 0]);
    for offset in [0, 255] {
        let name = Name::parse(&packet, offset).unwrap().0;
        assert_eq!(name.wire_len(), 255);
        assert_eq!(name.as_uncompressed(), Some(&packet[..255]));
        let mut output = [0xa5; 256];
        let error = name.write_uncompressed(&mut output[..254]).unwrap_err();
        assert_eq!(error.kind, ErrorKind::BufferTooSmall { needed: 255 });
        assert_eq!(output, [0xa5; 256]);
        assert_eq!(name.write_uncompressed(&mut output).unwrap(), 255);
        assert_eq!(&output[..255], &packet[..255]);
        assert_eq!(output[255], 0xa5);
    }
}

#[test]
fn question_continuation_preserves_remaining_sections_and_fused_state() {
    use zdwire::{Class, CompressionEntry, Header, MessageBuilder, RecordData, Section, Type};
    let mut output = [0; 128];
    let mut table = [CompressionEntry::EMPTY; 8];
    let name = Name::from_wire(b"\x01a\0").unwrap();
    let mut builder =
        MessageBuilder::with_compression(&mut output, Header::default(), &mut table).unwrap();
    builder.add_question(name, Type::A, Class::IN).unwrap();
    builder.add_question(name, Type::AAAA, Class::IN).unwrap();
    for section in [Section::Answer, Section::Authority, Section::Additional] {
        builder
            .add_record(section, name, Class::IN, 1, RecordData::A([192, 0, 2, 1]))
            .unwrap();
    }
    let message = MessageView::parse(builder.as_bytes()).unwrap();
    for consumed in 0..=2 {
        let mut questions = message.questions();
        for _ in 0..consumed {
            questions.next().unwrap().unwrap();
        }
        if consumed == 2 {
            assert!(questions.next().is_none());
            assert!(questions.next().is_none());
        }
        let mut records = questions.into_records().unwrap();
        for section in [Section::Answer, Section::Authority, Section::Additional] {
            let record = records.next().unwrap().unwrap();
            assert_eq!(record.section, section);
            assert_eq!(record.name, name);
            assert_eq!(record.rdata, &[192, 0, 2, 1]);
        }
        assert!(records.next().is_none());
        assert!(records.next().is_none());
    }
    // One complete question followed by a truncated label.
    let invalid = b"\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\x01\0\x01\x03x";
    let message = MessageView::parse(invalid).unwrap();
    let mut questions = message.questions();
    questions.next().unwrap().unwrap();
    let before_error = questions.clone().into_records().unwrap_err();
    let error = questions.next().unwrap().unwrap_err();
    assert_eq!(error, before_error);
    assert_eq!(error.offset, invalid.len());
    assert_eq!(questions.size_hint(), (0, Some(0)));
    assert!(questions.next().is_none());
    assert!(questions.next().is_none());
    assert_eq!(questions.into_records().unwrap_err(), error);
}
