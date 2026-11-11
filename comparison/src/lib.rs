//! Equivalent wire traversals used by both differential tests and timings.

pub mod encode;
pub mod fixtures;

use domain::base::Message;
use domain::base::name::{ParsedName, ToName};
use domain::base::opt::UnknownOptData;
use domain::base::rdata::{ComposeRecordData, UnknownRecordData};
use domain::rdata::AllRecordData;
use zdwire::{MessageView, Name, Rdata};

/// Allocation-free rejection marker; detailed errors are outside timed work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rejected;

#[derive(Default)]
struct Digest(u64);

impl Digest {
    #[inline]
    fn number(&mut self, value: u64) {
        self.0 = self.0.rotate_left(7) ^ value;
    }

    #[inline]
    fn bytes(&mut self, bytes: &[u8]) {
        self.number(bytes.len() as u64);
        if let Some(first) = bytes.first() {
            self.number(u64::from(*first));
            self.number(u64::from(*bytes.last().unwrap()));
        }
    }

    #[inline]
    fn zname(&mut self, name: Name<'_>) {
        for label in name.labels() {
            self.bytes(label);
        }
        self.number(0);
    }

    #[inline]
    fn dname(&mut self, name: &ParsedName<&[u8]>) {
        for label in name.iter() {
            if !label.is_root() {
                self.bytes(label.as_slice());
            }
        }
        self.number(0);
    }
}

/// Read all section headers, expand every name, and parse supported RDATA.
/// No formatting, allocating, strict message validation pass, or I/O is timed.
pub fn zdwire_typed(wire: &[u8]) -> Result<u64, zdwire::Error> {
    let message = MessageView::parse(wire)?;
    let mut digest = Digest::default();
    let h = message.header();
    for n in [
        h.id,
        h.flags,
        h.questions,
        h.answers,
        h.authorities,
        h.additionals,
    ] {
        digest.number(u64::from(n));
    }
    let mut questions = message.questions();
    for question in questions.by_ref() {
        let question = question?;
        digest.zname(question.name);
        digest.number(u64::from(question.qtype.0));
        digest.number(u64::from(question.qclass.0));
    }
    for record in questions.into_records()? {
        let record = record?;
        digest.zname(record.name);
        digest.number(u64::from(record.rr_type.0));
        digest.number(u64::from(record.class.0));
        digest.number(u64::from(record.ttl));
        zdigest(&mut digest, record.data()?);
    }
    Ok(digest.0)
}

fn zdigest(digest: &mut Digest, data: Rdata<'_>) {
    match data {
        Rdata::A(address) => digest.bytes(address),
        Rdata::Aaaa(address) => digest.bytes(address),
        Rdata::Cname(name) | Rdata::Ns(name) | Rdata::Ptr(name) => digest.zname(name),
        Rdata::Mx {
            preference,
            exchange,
        } => {
            digest.number(u64::from(preference));
            digest.zname(exchange);
        }
        Rdata::Txt(text) => {
            for string in text.iter() {
                digest.bytes(string);
            }
        }
        Rdata::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            digest.zname(mname);
            digest.zname(rname);
            for number in [serial, refresh, retry, expire, minimum] {
                digest.number(u64::from(number));
            }
        }
        Rdata::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            for number in [priority, weight, port] {
                digest.number(u64::from(number));
            }
            digest.zname(target);
        }
        Rdata::Caa { flags, tag, value } => {
            digest.number(u64::from(flags));
            digest.number(tag.len() as u64);
            digest.bytes(value);
        }
        Rdata::Opt(options) => {
            for option in options.options() {
                digest.number(u64::from(option.code));
                digest.bytes(option.data);
            }
        }
        Rdata::Unknown { rdata, .. } => digest.bytes(rdata),
    }
}

/// The domain counterpart to [`zdwire_typed`], using its streaming section API.
pub fn domain_typed(wire: &[u8]) -> Result<u64, Rejected> {
    let message = Message::from_slice(wire).map_err(|_| Rejected)?;
    let mut digest = Digest::default();
    for bytes in wire[..12].chunks_exact(2) {
        digest.number(u64::from(u16::from_be_bytes([bytes[0], bytes[1]])));
    }
    let mut questions = message.question();
    for question in questions.by_ref() {
        let question = question.map_err(|_| Rejected)?;
        digest.dname(question.qname());
        digest.number(u64::from(question.qtype().to_int()));
        digest.number(u64::from(question.qclass().to_int()));
    }
    let mut section = Some(questions.next_section().map_err(|_| Rejected)?);
    while let Some(mut records) = section {
        for record in records.by_ref() {
            let record = record.map_err(|_| Rejected)?;
            let record = record
                .into_any_record::<AllRecordData<_, _>>()
                .map_err(|_| Rejected)?;
            digest.dname(record.owner());
            digest.number(u64::from(record.rtype().to_int()));
            digest.number(u64::from(record.class().to_int()));
            digest.number(u64::from(record.ttl().as_secs()));
            ddigest(&mut digest, record.data())?;
        }
        section = records.next_section().map_err(|_| Rejected)?;
    }
    Ok(digest.0)
}

/// A domain baseline specialized to the same RR set as zdwire, avoiding the
/// larger AllRecordData enum while preserving the same parsing and digest work.
pub fn domain_specialized(wire: &[u8]) -> Result<u64, Rejected> {
    let message = Message::from_slice(wire).map_err(|_| Rejected)?;
    let mut digest = Digest::default();
    for bytes in wire[..12].chunks_exact(2) {
        digest.number(u64::from(u16::from_be_bytes([bytes[0], bytes[1]])));
    }
    let mut questions = message.question();
    for question in questions.by_ref() {
        let question = question.map_err(|_| Rejected)?;
        digest.dname(question.qname());
        digest.number(u64::from(question.qtype().to_int()));
        digest.number(u64::from(question.qclass().to_int()));
    }
    let mut section = Some(questions.next_section().map_err(|_| Rejected)?);
    while let Some(mut records) = section {
        for record in records.by_ref() {
            let record = record.map_err(|_| Rejected)?;
            digest.dname(&record.owner());
            digest.number(u64::from(record.rtype().to_int()));
            digest.number(u64::from(record.class().to_int()));
            digest.number(u64::from(record.ttl().as_secs()));
            dspecialized(&mut digest, record)?;
        }
        section = records.next_section().map_err(|_| Rejected)?;
    }
    Ok(digest.0)
}

fn dspecialized(
    digest: &mut Digest,
    record: domain::base::ParsedRecord<'_, [u8]>,
) -> Result<(), Rejected> {
    use domain::rdata::{A, Aaaa, Caa, Cname, Mx, Ns, Ptr, Soa, Srv, Txt};
    macro_rules! data {
        ($typ:ty) => {
            record
                .into_record::<$typ>()
                .map_err(|_| Rejected)?
                .ok_or(Rejected)?
                .into_data()
        };
    }
    match record.rtype().to_int() {
        1 => digest.bytes(&data!(A).addr().octets()),
        28 => digest.bytes(&data!(Aaaa).addr().octets()),
        2 => digest.dname(data!(Ns<ParsedName<&[u8]>>).nsdname()),
        5 => digest.dname(data!(Cname<ParsedName<&[u8]>>).cname()),
        12 => digest.dname(data!(Ptr<ParsedName<&[u8]>>).ptrdname()),
        15 => {
            let data = data!(Mx<ParsedName<&[u8]>>);
            digest.number(u64::from(data.preference()));
            digest.dname(data.exchange());
        }
        16 => {
            for string in data!(Txt<&[u8]>).iter() {
                digest.bytes(string);
            }
        }
        6 => {
            let data = data!(Soa<ParsedName<&[u8]>>);
            digest.dname(data.mname());
            digest.dname(data.rname());
            for number in [
                data.serial().into_int(),
                data.refresh().as_secs(),
                data.retry().as_secs(),
                data.expire().as_secs(),
                data.minimum().as_secs(),
            ] {
                digest.number(u64::from(number));
            }
        }
        33 => {
            let data = data!(Srv<ParsedName<&[u8]>>);
            for number in [data.priority(), data.weight(), data.port()] {
                digest.number(u64::from(number));
            }
            digest.dname(data.target());
        }
        257 => {
            let data = data!(Caa<&[u8]>);
            digest.number(u64::from(data.flags().bits()));
            digest.number(u64::from(data.tag().compose_len() - 1));
            digest.bytes(data.value());
        }
        41 => {
            let data = data!(domain::base::opt::Opt<&[u8]>);
            for option in data.iter::<UnknownOptData<_>>() {
                let option = option.map_err(|_| Rejected)?;
                digest.number(u64::from(option.code().to_int()));
                digest.bytes(option.data());
            }
        }
        _ => digest.bytes(data!(UnknownRecordData<&[u8]>).data()),
    }
    Ok(())
}

fn ddigest(
    digest: &mut Digest,
    data: &AllRecordData<&[u8], ParsedName<&[u8]>>,
) -> Result<(), Rejected> {
    match data {
        AllRecordData::A(data) => digest.bytes(&data.addr().octets()),
        AllRecordData::Aaaa(data) => digest.bytes(&data.addr().octets()),
        AllRecordData::Cname(data) => digest.dname(data.cname()),
        AllRecordData::Ns(data) => digest.dname(data.nsdname()),
        AllRecordData::Ptr(data) => digest.dname(data.ptrdname()),
        AllRecordData::Mx(data) => {
            digest.number(u64::from(data.preference()));
            digest.dname(data.exchange());
        }
        AllRecordData::Txt(data) => {
            for string in data.iter() {
                digest.bytes(string);
            }
        }
        AllRecordData::Soa(data) => {
            digest.dname(data.mname());
            digest.dname(data.rname());
            for number in [
                data.serial().into_int(),
                data.refresh().as_secs(),
                data.retry().as_secs(),
                data.expire().as_secs(),
                data.minimum().as_secs(),
            ] {
                digest.number(u64::from(number));
            }
        }
        AllRecordData::Srv(data) => {
            for number in [data.priority(), data.weight(), data.port()] {
                digest.number(u64::from(number));
            }
            digest.dname(data.target());
        }
        AllRecordData::Caa(data) => {
            digest.number(u64::from(data.flags().bits()));
            digest.number(u64::from(data.tag().compose_len() - 1));
            digest.bytes(data.value());
        }
        AllRecordData::Opt(data) => {
            for option in data.iter::<UnknownOptData<_>>() {
                let option = option.map_err(|_| Rejected)?;
                digest.number(u64::from(option.code().to_int()));
                digest.bytes(option.data());
            }
        }
        AllRecordData::Unknown(data) => digest.bytes(data.data()),
        _ => return Err(Rejected),
    }
    Ok(())
}

/// Raw-record traversal: same framing/owner-name checks, opaque RDATA in both.
pub fn zdwire_raw(wire: &[u8]) -> Result<u64, zdwire::Error> {
    let message = MessageView::parse(wire)?;
    let mut digest = Digest::default();
    let mut questions = message.questions();
    for question in questions.by_ref() {
        let question = question?;
        digest.zname(question.name);
        digest.number(u64::from(question.qtype.0));
        digest.number(u64::from(question.qclass.0));
    }
    for record in questions.into_records()? {
        let record = record?;
        digest.zname(record.name);
        digest.number(u64::from(record.rr_type.0));
        digest.number(u64::from(record.class.0));
        digest.number(u64::from(record.ttl));
        digest.bytes(record.rdata);
    }
    Ok(digest.0)
}

pub fn domain_raw(wire: &[u8]) -> Result<u64, Rejected> {
    let message = Message::from_slice(wire).map_err(|_| Rejected)?;
    let mut digest = Digest::default();
    let mut questions = message.question();
    for question in questions.by_ref() {
        let question = question.map_err(|_| Rejected)?;
        digest.dname(question.qname());
        digest.number(u64::from(question.qtype().to_int()));
        digest.number(u64::from(question.qclass().to_int()));
    }
    let mut section = Some(questions.next_section().map_err(|_| Rejected)?);
    while let Some(mut records) = section {
        while let Some(record) = records.next() {
            let record = record.map_err(|_| Rejected)?;
            let end = records.pos();
            let rdata = &wire[end - usize::from(record.rdlen())..end];
            digest.dname(&record.owner());
            digest.number(u64::from(record.rtype().to_int()));
            digest.number(u64::from(record.class().to_int()));
            digest.number(u64::from(record.ttl().as_secs()));
            digest.bytes(rdata);
        }
        section = records.next_section().map_err(|_| Rejected)?;
    }
    Ok(digest.0)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub header: [u8; 12],
    pub questions: Vec<(Vec<u8>, u16, u16)>,
    pub records: Vec<SnapshotRecord>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SnapshotRecord {
    pub section: u8,
    pub name: Vec<u8>,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

fn zname(out: &mut Vec<u8>, name: Name<'_>) {
    for label in name.labels() {
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
}

fn zcanonical(data: Rdata<'_>) -> Vec<u8> {
    let mut bytes = Vec::new();
    match data {
        Rdata::A(data) => bytes.extend_from_slice(data),
        Rdata::Aaaa(data) => bytes.extend_from_slice(data),
        Rdata::Ns(name) | Rdata::Cname(name) | Rdata::Ptr(name) => zname(&mut bytes, name),
        Rdata::Mx {
            preference,
            exchange,
        } => {
            bytes.extend_from_slice(&preference.to_be_bytes());
            zname(&mut bytes, exchange);
        }
        Rdata::Txt(txt) => {
            for text in txt.iter() {
                bytes.push(text.len() as u8);
                bytes.extend_from_slice(text);
            }
        }
        Rdata::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            zname(&mut bytes, mname);
            zname(&mut bytes, rname);
            for value in [serial, refresh, retry, expire, minimum] {
                bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
        Rdata::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            for value in [priority, weight, port] {
                bytes.extend_from_slice(&value.to_be_bytes());
            }
            zname(&mut bytes, target);
        }
        Rdata::Caa { flags, tag, value } => {
            bytes.extend_from_slice(&[flags, tag.len() as u8]);
            bytes.extend_from_slice(tag);
            bytes.extend_from_slice(value);
        }
        Rdata::Opt(opt) => {
            for option in opt.options() {
                bytes.extend_from_slice(&option.code.to_be_bytes());
                bytes.extend_from_slice(&(option.data.len() as u16).to_be_bytes());
                bytes.extend_from_slice(option.data);
            }
        }
        Rdata::Unknown { rdata, .. } => bytes.extend_from_slice(rdata),
    }
    bytes
}

pub fn zdwire_snapshot(wire: &[u8]) -> Result<Snapshot, zdwire::Error> {
    let message = MessageView::parse(wire)?;
    message.validate()?;
    let mut snapshot = Snapshot {
        header: wire[..12].try_into().unwrap(),
        questions: Vec::new(),
        records: Vec::new(),
    };
    let mut questions = message.questions();
    for question in questions.by_ref() {
        let question = question?;
        let mut name = Vec::new();
        zname(&mut name, question.name);
        snapshot
            .questions
            .push((name, question.qtype.0, question.qclass.0));
    }
    for record in questions.into_records()? {
        let record = record?;
        let mut name = Vec::new();
        zname(&mut name, record.name);
        let section = match record.section {
            zdwire::Section::Answer => 0,
            zdwire::Section::Authority => 1,
            zdwire::Section::Additional => 2,
        };
        snapshot.records.push(SnapshotRecord {
            section,
            name,
            rr_type: record.rr_type.0,
            class: record.class.0,
            ttl: record.ttl,
            data: zcanonical(record.data()?),
        });
    }
    Ok(snapshot)
}

pub fn domain_snapshot(wire: &[u8]) -> Result<Snapshot, String> {
    let message = Message::from_slice(wire).map_err(|e| e.to_string())?;
    let mut snapshot = Snapshot {
        header: wire[..12].try_into().unwrap(),
        questions: Vec::new(),
        records: Vec::new(),
    };
    let mut questions = message.question();
    for question in questions.by_ref() {
        let question = question.map_err(|e| e.to_string())?;
        let mut name = Vec::new();
        question.qname().compose(&mut name).unwrap();
        snapshot
            .questions
            .push((name, question.qtype().to_int(), question.qclass().to_int()));
    }
    let mut section = Some(questions.next_section().map_err(|e| e.to_string())?);
    let mut section_index = 0;
    while let Some(mut records) = section {
        for record in records.by_ref() {
            let record = record.map_err(|e| e.to_string())?;
            let record = record
                .into_any_record::<AllRecordData<_, _>>()
                .map_err(|e| e.to_string())?;
            let mut name = Vec::new();
            record.owner().compose(&mut name).unwrap();
            let mut data = octseq::array::Array::<65535>::new();
            record.data().compose_rdata(&mut data).unwrap();
            snapshot.records.push(SnapshotRecord {
                section: section_index,
                name,
                rr_type: record.rtype().to_int(),
                class: record.class().to_int(),
                ttl: record.ttl().as_secs(),
                data: data.as_slice().to_vec(),
            });
        }
        section = records.next_section().map_err(|e| e.to_string())?;
        section_index += 1;
    }
    Ok(snapshot)
}
