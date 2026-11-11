//! Serialize identical inputs to reusable caller buffers in both libraries.

use domain::base::iana::{Class as DClass, Rtype};
use domain::base::message_builder::StaticCompressor;
use domain::base::rdata::UnknownRecordData;
use domain::base::wire::Composer;
use domain::base::{MessageBuilder as DBuilder, Name as DName, Ttl};
use domain::rdata::{A, Txt};
use octseq::builder::{OctetsBuilder, ShortBuf, Truncate};
use zdwire::{Class, CompressionEntry, Header, MessageBuilder, Name, RecordData, Section, Type};

use crate::fixtures::{WWW, txt_wire};

pub struct EncodeCase {
    pub name: &'static str,
    pub records: usize,
    pub rr_type: u16,
    pub data: Vec<u8>,
    pub edns: bool,
    pub question: bool,
}

pub fn cases() -> Vec<EncodeCase> {
    vec![
        EncodeCase {
            name: "query",
            records: 0,
            rr_type: 1,
            data: vec![],
            edns: false,
            question: true,
        },
        EncodeCase {
            name: "64-answers",
            records: 64,
            rr_type: 1,
            data: vec![],
            edns: false,
            question: true,
        },
        EncodeCase {
            name: "512-repeated",
            records: 512,
            rr_type: 1,
            data: vec![],
            edns: false,
            question: true,
        },
        EncodeCase {
            name: "64-txt",
            records: 64,
            rr_type: 16,
            data: txt_wire(8, 80),
            edns: false,
            question: true,
        },
        EncodeCase {
            name: "edns",
            records: 0,
            rr_type: 1,
            data: vec![0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8],
            edns: true,
            question: true,
        },
        EncodeCase {
            name: "65535-byte",
            records: 1,
            rr_type: 65280,
            data: vec![0x5a; 65512],
            edns: false,
            question: false,
        },
    ]
}

pub fn zdwire(case: &EncodeCase, output: &mut [u8], compressed: bool) -> usize {
    let flags = if case.records == 0 { 0x0100 } else { 0x8180 };
    let header = Header::new(0x4a6f, flags);
    let mut table = [CompressionEntry::EMPTY; 24];
    let mut builder = if compressed {
        MessageBuilder::with_compression(output, header, &mut table).unwrap()
    } else {
        MessageBuilder::new(output, header).unwrap()
    };
    let name = Name::from_wire(if case.question { WWW } else { &[0] }).unwrap();
    if case.question {
        builder.add_question(name, Type::A, Class::IN).unwrap();
    }
    for i in 0..case.records {
        let data = match case.rr_type {
            1 => RecordData::A([192, 0, 2, i as u8]),
            16 => RecordData::Txt(&case.data),
            other => RecordData::Unknown {
                rr_type: Type(other),
                rdata: &case.data,
            },
        };
        builder
            .add_record(Section::Answer, name, Class::IN, 300, data)
            .unwrap();
    }
    if case.edns {
        builder.add_opt(1232, 0, 0, 0x8000, &case.data).unwrap();
    }
    builder.len()
}

/// A bounded slice adapter, implementing domain's documented target traits.
/// The buffer is allocated by the harness outside the timed region.
struct CallerBuffer<'a> {
    data: &'a mut [u8],
    len: usize,
}

impl AsRef<[u8]> for CallerBuffer<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl AsMut<[u8]> for CallerBuffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

impl OctetsBuilder for CallerBuffer<'_> {
    type AppendError = ShortBuf;
    fn append_slice(&mut self, bytes: &[u8]) -> Result<(), ShortBuf> {
        if bytes.len() > self.data.len() - self.len {
            return Err(ShortBuf);
        }
        let end = self.len + bytes.len();
        self.data[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

impl Truncate for CallerBuffer<'_> {
    fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }
}

impl Composer for CallerBuffer<'_> {}

pub fn domain(case: &EncodeCase, output: &mut [u8], compressed: bool) -> usize {
    let target = CallerBuffer {
        data: output,
        len: 0,
    };
    if compressed {
        domain_target(case, StaticCompressor::new(target))
    } else {
        domain_target(case, target)
    }
}

fn domain_target<T: Composer>(case: &EncodeCase, target: T) -> usize {
    let mut builder = DBuilder::from_target(target).ok().unwrap();
    builder.header_mut().set_id(0x4a6f);
    builder.header_mut().set_rd(true);
    if case.records != 0 {
        builder.header_mut().set_qr(true);
        builder.header_mut().set_ra(true);
    }
    let name = DName::from_slice(if case.question { WWW } else { &[0] }).unwrap();
    let mut question = builder.question();
    if case.question {
        question.push((name, Rtype::A, DClass::IN)).unwrap();
    }
    let mut answer = question.answer();
    for i in 0..case.records {
        match case.rr_type {
            1 => answer
                .push((
                    name,
                    DClass::IN,
                    Ttl::from_secs(300),
                    A::from_octets(192, 0, 2, i as u8),
                ))
                .unwrap(),
            16 => answer
                .push((
                    name,
                    DClass::IN,
                    Ttl::from_secs(300),
                    Txt::from_octets(case.data.as_slice()).unwrap(),
                ))
                .unwrap(),
            other => answer
                .push((
                    name,
                    DClass::IN,
                    Ttl::from_secs(300),
                    UnknownRecordData::from_octets(Rtype::from_int(other), case.data.as_slice())
                        .unwrap(),
                ))
                .unwrap(),
        }
    }
    let mut additional = answer.additional();
    if case.edns {
        let name = DName::from_slice(&[0]).unwrap();
        let data = domain::base::opt::Opt::from_octets(case.data.as_slice()).unwrap();
        additional
            .push((name, DClass::from_int(1232), Ttl::from_secs(0x8000), data))
            .unwrap();
    }
    additional.finish().as_ref().len()
}

/// Re-encode every supported parsed RDATA type for cross-library round trips.
pub fn reencode_zdwire(wire: &[u8], output: &mut [u8], compressed: bool) -> usize {
    let view = zdwire::MessageView::parse(wire).unwrap();
    let mut table = [CompressionEntry::EMPTY; 24];
    let mut builder = if compressed {
        MessageBuilder::with_compression(output, view.header(), &mut table).unwrap()
    } else {
        MessageBuilder::new(output, view.header()).unwrap()
    };
    let mut questions = view.questions();
    for question in questions.by_ref() {
        let question = question.unwrap();
        builder
            .add_question(question.name, question.qtype, question.qclass)
            .unwrap();
    }
    for record in questions.into_records().unwrap() {
        let record = record.unwrap();
        use zdwire::Rdata;
        let data = match record.data().unwrap() {
            Rdata::A(value) => RecordData::A(*value),
            Rdata::Aaaa(value) => RecordData::Aaaa(*value),
            Rdata::Ns(name) => RecordData::Ns(name),
            Rdata::Cname(name) => RecordData::Cname(name),
            Rdata::Ptr(name) => RecordData::Ptr(name),
            Rdata::Mx {
                preference,
                exchange,
            } => RecordData::Mx {
                preference,
                exchange,
            },
            Rdata::Txt(txt) => RecordData::Txt(txt.as_bytes()),
            Rdata::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => RecordData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            },
            Rdata::Srv {
                priority,
                weight,
                port,
                target,
            } => RecordData::Srv {
                priority,
                weight,
                port,
                target,
            },
            Rdata::Caa { flags, tag, value } => RecordData::Caa { flags, tag, value },
            Rdata::Opt(opt) => {
                builder
                    .add_opt(
                        opt.udp_payload_size(),
                        opt.extended_rcode(),
                        opt.version(),
                        opt.flags(),
                        record.rdata,
                    )
                    .unwrap();
                continue;
            }
            Rdata::Unknown { rr_type, rdata } => RecordData::Unknown { rr_type, rdata },
        };
        builder
            .add_record(record.section, record.name, record.class, record.ttl, data)
            .unwrap();
    }
    builder.len()
}

pub fn reencode_domain(wire: &[u8], output: &mut [u8], compressed: bool) -> usize {
    let target = CallerBuffer {
        data: output,
        len: 0,
    };
    if compressed {
        reencode_domain_target(wire, StaticCompressor::new(target))
    } else {
        reencode_domain_target(wire, target)
    }
}

fn reencode_domain_target<T: Composer>(wire: &[u8], target: T) -> usize {
    use domain::base::Message;
    use domain::rdata::AllRecordData;
    let view = Message::from_slice(wire).unwrap();
    let mut builder = DBuilder::from_target(target).ok().unwrap();
    *builder.header_mut() = view.header();
    let mut question = builder.question();
    let mut questions = view.question();
    for item in questions.by_ref() {
        question.push(item.unwrap()).unwrap();
    }
    let mut records = questions.next_section().unwrap();
    let mut answer = question.answer();
    for record in records.by_ref() {
        answer
            .push(
                record
                    .unwrap()
                    .into_any_record::<AllRecordData<_, _>>()
                    .unwrap(),
            )
            .unwrap();
    }
    let mut records = records.next_section().unwrap().unwrap();
    let mut authority = answer.authority();
    for record in records.by_ref() {
        authority
            .push(
                record
                    .unwrap()
                    .into_any_record::<AllRecordData<_, _>>()
                    .unwrap(),
            )
            .unwrap();
    }
    let records = records.next_section().unwrap().unwrap();
    let mut additional = authority.additional();
    for record in records {
        additional
            .push(
                record
                    .unwrap()
                    .into_any_record::<AllRecordData<_, _>>()
                    .unwrap(),
            )
            .unwrap();
    }
    additional.finish().as_ref().len()
}
