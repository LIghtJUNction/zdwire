use crate::{Error, ErrorKind, MAX_MESSAGE_LEN, Name, Rdata, take, u16_at};
use core::iter::FusedIterator;

/// DNS RR type. Unknown numeric values are preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Type(pub u16);
impl Type {
    /// IPv4 address.
    pub const A: Self = Self(1);
    /// Authoritative name server.
    pub const NS: Self = Self(2);
    /// Canonical name.
    pub const CNAME: Self = Self(5);
    /// Start of authority.
    pub const SOA: Self = Self(6);
    /// Domain-name pointer.
    pub const PTR: Self = Self(12);
    /// Mail exchange.
    pub const MX: Self = Self(15);
    /// Character-string data.
    pub const TXT: Self = Self(16);
    /// IPv6 address.
    pub const AAAA: Self = Self(28);
    /// Service location.
    pub const SRV: Self = Self(33);
    /// EDNS pseudo-record.
    pub const OPT: Self = Self(41);
    /// Certificate authority authorization.
    pub const CAA: Self = Self(257);
    /// Wildcard query type.
    pub const ANY: Self = Self(255);
}

/// DNS class. In OPT records the numeric field is a UDP payload size.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Class(pub u16);
impl Class {
    /// Internet class.
    pub const IN: Self = Self(1);
    /// CHAOS class.
    pub const CH: Self = Self(3);
    /// Hesiod class.
    pub const HS: Self = Self(4);
    /// No class (dynamic update).
    pub const NONE: Self = Self(254);
    /// Wildcard class.
    pub const ANY: Self = Self(255);
}

/// A DNS header in host byte order. All flag bits are retained.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Header {
    /// Transaction identifier.
    pub id: u16,
    /// Flags, opcode, and base response code in their original bit positions.
    pub flags: u16,
    /// QDCOUNT.
    pub questions: u16,
    /// ANCOUNT.
    pub answers: u16,
    /// NSCOUNT.
    pub authorities: u16,
    /// ARCOUNT.
    pub additionals: u16,
}

impl Header {
    /// Wire size of a DNS header.
    pub const LEN: usize = 12;
    /// Response flag.
    pub const QR: u16 = 0x8000;
    /// Authoritative answer flag.
    pub const AA: u16 = 0x0400;
    /// Truncated flag.
    pub const TC: u16 = 0x0200;
    /// Recursion desired flag.
    pub const RD: u16 = 0x0100;
    /// Recursion available flag.
    pub const RA: u16 = 0x0080;
    /// Authenticated data flag; this library does not authenticate DNSSEC.
    pub const AD: u16 = 0x0020;
    /// Checking disabled flag.
    pub const CD: u16 = 0x0010;

    /// Creates a header with zero section counts.
    pub const fn new(id: u16, flags: u16) -> Self {
        Self {
            id,
            flags,
            questions: 0,
            answers: 0,
            authorities: 0,
            additionals: 0,
        }
    }

    /// Reads the first 12 bytes as a header without interpreting the body.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let b = take(input, 0, Self::LEN)?;
        Ok(Self {
            id: u16::from_be_bytes([b[0], b[1]]),
            flags: u16::from_be_bytes([b[2], b[3]]),
            questions: u16::from_be_bytes([b[4], b[5]]),
            answers: u16::from_be_bytes([b[6], b[7]]),
            authorities: u16::from_be_bytes([b[8], b[9]]),
            additionals: u16::from_be_bytes([b[10], b[11]]),
        })
    }

    /// Writes exactly 12 bytes. Capacity failure leaves the output untouched.
    pub fn write(self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < Self::LEN {
            return Err(Error::new(
                ErrorKind::BufferTooSmall { needed: Self::LEN },
                output.len(),
            ));
        }
        for (out, word) in output[..Self::LEN].as_chunks_mut::<2>().0.iter_mut().zip([
            self.id,
            self.flags,
            self.questions,
            self.answers,
            self.authorities,
            self.additionals,
        ]) {
            out.copy_from_slice(&word.to_be_bytes());
        }
        Ok(Self::LEN)
    }

    /// Four-bit opcode.
    pub const fn opcode(self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }
    /// Four-bit base response code; combine with OPT for the extended code.
    pub const fn rcode(self) -> u8 {
        (self.flags & 0x0f) as u8
    }
    /// Whether this is a response.
    pub const fn is_response(self) -> bool {
        self.flags & Self::QR != 0
    }
    /// Whether the sender set TC.
    pub const fn truncated(self) -> bool {
        self.flags & Self::TC != 0
    }
}

/// A resource record's section. Questions have a separate wire format.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Section {
    /// Answer section.
    Answer,
    /// Authority section.
    Authority,
    /// Additional section.
    Additional,
}

/// Borrowed DNS packet with a decoded header and lazy record access.
#[derive(Clone, Copy, Debug)]
pub struct MessageView<'a> {
    data: &'a [u8],
    header: Header,
}

impl<'a> MessageView<'a> {
    /// Checks message size and header only. Use [`Self::validate`] when every
    /// field and the absence of trailing bytes must be verified immediately.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() > MAX_MESSAGE_LEN {
            return Err(Error::new(ErrorKind::MessageTooLong, MAX_MESSAGE_LEN));
        }
        Ok(Self {
            data,
            header: Header::parse(data)?,
        })
    }

    /// Parses and fully validates a complete packet.
    pub fn parse_strict(data: &'a [u8]) -> Result<Self, Error> {
        let view = Self::parse(data)?;
        view.validate()?;
        Ok(view)
    }

    /// Returns the decoded header.
    pub const fn header(self) -> Header {
        self.header
    }
    /// Returns the untouched original packet, excluding any transport framing.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.data
    }

    /// Iterates questions; each name and fixed fields are validated once.
    pub fn questions(self) -> Questions<'a> {
        Questions {
            data: self.data,
            pos: Header::LEN,
            remaining: self.header.questions,
            counts: [
                self.header.answers,
                self.header.authorities,
                self.header.additionals,
            ],
            error: None,
        }
    }

    /// Iterates all RRs in wire order. Questions are checked and skipped once.
    /// RR owner names and RDLENGTH are checked; typed RDATA is checked by
    /// [`Record::data`]. The iterator stops permanently after its first error.
    pub fn records(self) -> Records<'a> {
        Records {
            data: self.data,
            pos: Header::LEN,
            questions: self.header.questions,
            counts: [
                self.header.answers,
                self.header.authorities,
                self.header.additionals,
            ],
            section: 0,
            failed: false,
        }
    }

    /// Locates and iterates the answer section. Repeated calls repeat the scan.
    pub fn answers(self) -> Result<Records<'a>, Error> {
        self.section(0)
    }
    /// Locates and iterates the authority section, scanning preceding records.
    pub fn authorities(self) -> Result<Records<'a>, Error> {
        self.section(1)
    }
    /// Locates and iterates the additional section, scanning preceding records.
    pub fn additionals(self) -> Result<Records<'a>, Error> {
        self.section(2)
    }

    fn section(self, index: usize) -> Result<Records<'a>, Error> {
        let mut all = self.records();
        all.skip_questions()?;
        for section in 0..index {
            while all.counts[section] != 0 {
                parse_record(self.data, &mut all.pos, section)?;
                all.counts[section] -= 1;
            }
        }
        all.section = index;
        for count in &mut all.counts[index + 1..] {
            *count = 0;
        }
        Ok(all)
    }

    /// Fully validates questions, records, supported RDATA, single root OPT in
    /// Additional, and the exact end of the packet. Flags and unknown types are
    /// preserved; DNS resolver policy and DNSSEC verification are outside scope.
    pub fn validate(self) -> Result<(), Error> {
        let mut records = self.records();
        let mut opt = false;
        for result in records.by_ref() {
            let record = result?;
            record.data()?;
            if record.rr_type == Type::OPT {
                if opt {
                    return Err(Error::new(ErrorKind::DuplicateOpt, record.name.offset()));
                }
                opt = true;
            }
        }
        if records.pos != self.data.len() {
            return Err(Error::new(ErrorKind::TrailingData, records.pos));
        }
        Ok(())
    }
}

/// A borrowed, validated question.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Question<'a> {
    /// Queried name.
    pub name: Name<'a>,
    /// Requested RR type.
    pub qtype: Type,
    /// Requested class.
    pub qclass: Class,
}

#[inline]
fn parse_question<'a>(data: &'a [u8], pos: &mut usize) -> Result<Question<'a>, Error> {
    let (name, end) = Name::parse_bounded(data, *pos, data.len(), true)?;
    let b = take(data, end, 4)?;
    *pos = end + 4;
    Ok(Question {
        name,
        qtype: Type(u16::from_be_bytes([b[0], b[1]])),
        qclass: Class(u16::from_be_bytes([b[2], b[3]])),
    })
}

/// Fused, fallible question iterator. No allocation and no recursive parsing.
#[derive(Clone, Debug)]
pub struct Questions<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: u16,
    counts: [u16; 3],
    error: Option<Error>,
}
impl<'a> Questions<'a> {
    /// Continues into all resource-record sections without reparsing consumed
    /// questions. Any unconsumed questions are validated and skipped once.
    /// An earlier question error is returned again, preserving its offset.
    pub fn into_records(self) -> Result<Records<'a>, Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let mut records = Records {
            data: self.data,
            pos: self.pos,
            questions: self.remaining,
            counts: self.counts,
            section: 0,
            failed: false,
        };
        records.skip_questions()?;
        Ok(records)
    }
}
impl<'a> Iterator for Questions<'a> {
    type Item = Result<Question<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.error.is_some() || self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let result = parse_question(self.data, &mut self.pos);
        self.error = result.as_ref().err().copied();
        Some(result)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (
            0,
            Some(if self.error.is_some() {
                0
            } else {
                self.remaining as usize
            }),
        )
    }
}
impl FusedIterator for Questions<'_> {}

/// A zero-copy RR with validated owner, fixed fields, and RDATA bounds.
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    /// Owner name, retaining access to packet compression targets.
    pub name: Name<'a>,
    /// RR type; unknown types remain accessible as raw bytes.
    pub rr_type: Type,
    /// Class, or advertised UDP payload size for OPT.
    pub class: Class,
    /// Time to live, or extended flags for OPT.
    pub ttl: u32,
    /// Exact original RDATA bytes. Compressed names reference the whole packet.
    pub rdata: &'a [u8],
    /// Section in which this record occurs.
    pub section: Section,
    pub(crate) message: &'a [u8],
    pub(crate) data_offset: u16,
}
impl<'a> Record<'a> {
    /// Validates and interprets supported RDATA. Unknown types stay opaque.
    #[inline]
    pub fn data(self) -> Result<Rdata<'a>, Error> {
        Rdata::parse(self)
    }
    /// Absolute packet offset of the first RDATA byte.
    pub const fn rdata_offset(self) -> usize {
        self.data_offset as usize
    }
}

#[inline]
fn parse_record<'a>(data: &'a [u8], pos: &mut usize, section: usize) -> Result<Record<'a>, Error> {
    let (name, end) = Name::parse_bounded(data, *pos, data.len(), true)?;
    let b = take(data, end, 10)?;
    let offset = end + 10;
    let len = u16_at(b, 8)? as usize;
    let rdata = take(data, offset, len)?;
    *pos = offset + len;
    Ok(Record {
        name,
        rr_type: Type(u16::from_be_bytes([b[0], b[1]])),
        class: Class(u16::from_be_bytes([b[2], b[3]])),
        ttl: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        rdata,
        section: match section {
            0 => Section::Answer,
            1 => Section::Authority,
            _ => Section::Additional,
        },
        message: data,
        data_offset: offset as u16,
    })
}

/// Fused fallible RR iterator across one or more sections.
#[derive(Clone, Debug)]
pub struct Records<'a> {
    data: &'a [u8],
    pos: usize,
    questions: u16,
    counts: [u16; 3],
    section: usize,
    failed: bool,
}
impl Records<'_> {
    fn skip_questions(&mut self) -> Result<(), Error> {
        while self.questions != 0 {
            parse_question(self.data, &mut self.pos)?;
            self.questions -= 1;
        }
        Ok(())
    }
}
impl<'a> Iterator for Records<'a> {
    type Item = Result<Record<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        if let Err(error) = self.skip_questions() {
            self.failed = true;
            return Some(Err(error));
        }
        while self.section < 3 && self.counts[self.section] == 0 {
            self.section += 1;
        }
        if self.section == 3 {
            return None;
        }
        self.counts[self.section] -= 1;
        let result = parse_record(self.data, &mut self.pos, self.section);
        self.failed = result.is_err();
        Some(result)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        // On a 16-bit target, sums of three u16 counts may overflow usize.
        let count = self
            .counts
            .iter()
            .fold(0usize, |sum, n| sum.saturating_add(*n as usize));
        (
            0,
            Some(if self.failed {
                0
            } else {
                count.saturating_add(usize::from(self.questions != 0))
            }),
        )
    }
}
impl FusedIterator for Records<'_> {}
