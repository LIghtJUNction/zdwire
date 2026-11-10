//! DNS message construction into caller-owned memory.

use crate::{Class, Error, ErrorKind, Header, Name, Section, Type};

/// One slot in a caller-provided name compression table.
///
/// Slots are direct-mapped: collisions may reduce compression, never correctness.
/// The encoder only indexes uncompressed names, so generated pointers have a
/// single hop. A table of 256 slots occupies 4 KiB on common targets.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompressionEntry {
    hash: u64,
    offset: u16,
    len: u8,
}

impl CompressionEntry {
    /// An unused compression-table slot.
    pub const EMPTY: Self = Self {
        hash: 0,
        offset: 0,
        len: 0,
    };
}

/// Typed resource data for message construction.
///
/// `Txt` contains the complete sequence of length-prefixed character strings.
/// Use `[0]` to encode one empty string. `Unknown` accepts unimplemented types
/// only; its opaque bytes are copied unchanged. Compressed pointers in unknown
/// RDATA cannot be relocated automatically.
#[derive(Clone, Copy, Debug)]
pub enum RecordData<'a> {
    /// IPv4 address.
    A([u8; 4]),
    /// IPv6 address.
    Aaaa([u8; 16]),
    /// Authoritative name server.
    Ns(Name<'a>),
    /// Canonical name.
    Cname(Name<'a>),
    /// Domain name pointer record.
    Ptr(Name<'a>),
    /// Mail exchange.
    Mx {
        /// Lower values have higher preference.
        preference: u16,
        /// Mail server name.
        exchange: Name<'a>,
    },
    /// One or more wire-format character strings.
    Txt(&'a [u8]),
    /// Start of authority.
    Soa {
        /// Primary name server.
        mname: Name<'a>,
        /// Responsible mailbox, encoded as a DNS name.
        rname: Name<'a>,
        /// Zone serial number.
        serial: u32,
        /// Refresh interval.
        refresh: u32,
        /// Retry interval.
        retry: u32,
        /// Expiration interval.
        expire: u32,
        /// Negative caching TTL.
        minimum: u32,
    },
    /// Service location. The target is emitted without name compression.
    Srv {
        /// Server priority.
        priority: u16,
        /// Relative server weight.
        weight: u16,
        /// Service port.
        port: u16,
        /// Server name.
        target: Name<'a>,
    },
    /// Certification Authority Authorization.
    Caa {
        /// Property flags.
        flags: u8,
        /// One to fifteen ASCII letters or digits.
        tag: &'a [u8],
        /// Opaque property value.
        value: &'a [u8],
    },
    /// Unimplemented RR type with opaque RDATA.
    Unknown {
        /// Numeric type code.
        rr_type: Type,
        /// Unmodified RDATA bytes.
        rdata: &'a [u8],
    },
}

impl RecordData<'_> {
    /// Returns the resource record's type code.
    pub const fn rr_type(&self) -> Type {
        match self {
            Self::A(_) => Type::A,
            Self::Aaaa(_) => Type::AAAA,
            Self::Ns(_) => Type::NS,
            Self::Cname(_) => Type::CNAME,
            Self::Ptr(_) => Type::PTR,
            Self::Mx { .. } => Type::MX,
            Self::Txt(_) => Type::TXT,
            Self::Soa { .. } => Type::SOA,
            Self::Srv { .. } => Type::SRV,
            Self::Caa { .. } => Type::CAA,
            Self::Unknown { rr_type, .. } => *rr_type,
        }
    }
}

/// Writes one DNS message into a caller-owned buffer.
///
/// Add questions, answers, authority records, and additional records in that
/// order. Empty sections may be skipped. Each append is transactional: on any
/// error the output bytes, section counts, and compression dictionary remain
/// unchanged. `BufferTooSmall { needed }` gives the exact total buffer capacity
/// required for that append with the current compression table.
///
/// The 65,535-byte DNS wire limit excludes the two-byte TCP framing prefix. This
/// builder never writes that transport-specific prefix.
pub struct MessageBuilder<'a> {
    buffer: &'a mut [u8],
    table: &'a mut [CompressionEntry],
    len: usize,
    counts: [u16; 4],
    section: u8,
    opt_written: bool,
}

impl<'a> MessageBuilder<'a> {
    /// Starts an uncompressed message.
    ///
    /// Only the supplied header's ID and flags are used. Section counts start
    /// at zero and are updated automatically.
    pub fn new(buffer: &'a mut [u8], header: Header) -> Result<Self, Error> {
        Self::with_compression(buffer, header, &mut [])
    }

    /// Starts a message with an optional caller-owned compression dictionary.
    ///
    /// The table is cleared on success. An empty table disables compression.
    /// Exact label bytes, including letter case, are preserved. Dictionary
    /// collisions affect only the encoded size; lookup work stays bounded.
    pub fn with_compression(
        buffer: &'a mut [u8],
        header: Header,
        table: &'a mut [CompressionEntry],
    ) -> Result<Self, Error> {
        if buffer.len() < 12 {
            return Err(Error::new(
                ErrorKind::BufferTooSmall { needed: 12 },
                buffer.len(),
            ));
        }
        buffer[..12].fill(0);
        buffer[..2].copy_from_slice(&header.id.to_be_bytes());
        buffer[2..4].copy_from_slice(&header.flags.to_be_bytes());
        table.fill(CompressionEntry::EMPTY);
        Ok(Self {
            buffer,
            table,
            len: 12,
            counts: [0; 4],
            section: 0,
            opt_written: false,
        })
    }

    /// Number of initialized message bytes, including the header.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// A DNS message always contains a header, so this returns `false`.
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Returns the initialized message prefix.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.len]
    }

    /// Finishes construction and returns the initialized caller-owned prefix.
    pub fn finish(self) -> &'a [u8] {
        &self.buffer[..self.len]
    }

    /// Appends a question, updating QDCOUNT.
    pub fn add_question(
        &mut self,
        name: Name<'_>,
        qtype: Type,
        qclass: Class,
    ) -> Result<(), Error> {
        self.check_section(0)?;
        let plan = self.plan_name(name, self.len, &[], true)?;
        let fields = self.len + plan.encoded_len();
        let end = fields + 4;
        self.reserve(end)?;
        self.write_name(&plan);
        self.put_u16(fields, qtype.0);
        self.put_u16(fields + 2, qclass.0);
        self.register_name(&plan);
        self.complete(0, end);
        Ok(())
    }

    /// Appends a typed resource record in the selected section.
    pub fn add_record(
        &mut self,
        section: Section,
        owner: Name<'_>,
        class: Class,
        ttl: u32,
        data: RecordData<'_>,
    ) -> Result<(), Error> {
        let section = section_index(section);
        self.check_section(section)?;
        let owner = self.plan_name(owner, self.len, &[], true)?;
        let fields = self.len + owner.encoded_len();
        let start = fields + 10;
        let mut first = NamePlan::EMPTY;
        let mut second = NamePlan::EMPTY;
        let rdlen = match data {
            RecordData::A(_) => 4,
            RecordData::Aaaa(_) => 16,
            RecordData::Ns(name) | RecordData::Cname(name) | RecordData::Ptr(name) => {
                first = self.plan_name(name, start, &[&owner], true)?;
                first.encoded_len()
            }
            RecordData::Mx { exchange, .. } => {
                first = self.plan_name(exchange, start + 2, &[&owner], true)?;
                2 + first.encoded_len()
            }
            RecordData::Txt(wire) => {
                validate_txt(wire, start)?;
                wire.len()
            }
            RecordData::Soa { mname, rname, .. } => {
                first = self.plan_name(mname, start, &[&owner], true)?;
                second =
                    self.plan_name(rname, start + first.encoded_len(), &[&owner, &first], true)?;
                first.encoded_len() + second.encoded_len() + 20
            }
            RecordData::Srv { target, .. } => {
                first = self.plan_name(target, start + 6, &[&owner], false)?;
                6 + first.encoded_len()
            }
            RecordData::Caa { tag, value, .. } => {
                if tag.is_empty() || tag.len() > 15 {
                    return Err(Error::new(ErrorKind::InvalidRdata, start + 1));
                }
                if let Some(index) = tag.iter().position(|b| !b.is_ascii_alphanumeric()) {
                    return Err(Error::new(ErrorKind::InvalidRdata, start + 2 + index));
                }
                checked_add(2 + tag.len(), value.len(), start)?
            }
            RecordData::Unknown { rr_type, rdata } => {
                if known_type(rr_type) {
                    return Err(Error::new(ErrorKind::InvalidRdata, start));
                }
                rdata.len()
            }
        };
        if rdlen > u16::MAX as usize {
            return Err(Error::new(ErrorKind::InvalidRdata, fields + 8));
        }
        let end = checked_add(start, rdlen, start)?;
        self.reserve(end)?;

        self.write_name(&owner);
        self.put_u16(fields, data.rr_type().0);
        self.put_u16(fields + 2, class.0);
        self.put_u32(fields + 4, ttl);
        self.put_u16(fields + 8, rdlen as u16);
        match data {
            RecordData::A(address) => self.buffer[start..end].copy_from_slice(&address),
            RecordData::Aaaa(address) => self.buffer[start..end].copy_from_slice(&address),
            RecordData::Ns(_) | RecordData::Cname(_) | RecordData::Ptr(_) => {
                self.write_name(&first);
            }
            RecordData::Mx { preference, .. } => {
                self.put_u16(start, preference);
                self.write_name(&first);
            }
            RecordData::Txt(wire) => self.buffer[start..end].copy_from_slice(wire),
            RecordData::Soa {
                serial,
                refresh,
                retry,
                expire,
                minimum,
                ..
            } => {
                self.write_name(&first);
                self.write_name(&second);
                let tail = second.offset + second.encoded_len();
                for (index, value) in [serial, refresh, retry, expire, minimum].iter().enumerate() {
                    self.put_u32(tail + index * 4, *value);
                }
            }
            RecordData::Srv {
                priority,
                weight,
                port,
                ..
            } => {
                self.put_u16(start, priority);
                self.put_u16(start + 2, weight);
                self.put_u16(start + 4, port);
                self.write_name(&first);
            }
            RecordData::Caa { flags, tag, value } => {
                self.buffer[start] = flags;
                self.buffer[start + 1] = tag.len() as u8;
                let tag_end = start + 2 + tag.len();
                self.buffer[start + 2..tag_end].copy_from_slice(tag);
                self.buffer[tag_end..end].copy_from_slice(value);
            }
            RecordData::Unknown { rdata, .. } => {
                self.buffer[start..end].copy_from_slice(rdata);
            }
        }
        self.register_name(&owner);
        self.register_name(&first);
        self.register_name(&second);
        self.complete(section, end);
        Ok(())
    }

    /// Appends one EDNS OPT record to the additional section.
    ///
    /// `options_wire` is a sequence of `(code: u16, length: u16, value)` in
    /// network byte order. Unknown option codes and EDNS versions are retained.
    /// Set bit `0x8000` in `flags` for the DNSSEC OK bit.
    pub fn add_opt(
        &mut self,
        udp_size: u16,
        extended_rcode: u8,
        version: u8,
        flags: u16,
        options_wire: &[u8],
    ) -> Result<(), Error> {
        self.check_section(3)?;
        if self.opt_written {
            return Err(Error::new(ErrorKind::DuplicateOpt, self.len));
        }
        let start = self.len + 11;
        if options_wire.len() > u16::MAX as usize {
            return Err(Error::new(ErrorKind::InvalidOpt, self.len + 9));
        }
        validate_options(options_wire, start)?;
        let end = checked_add(start, options_wire.len(), start)?;
        self.reserve(end)?;
        self.buffer[self.len] = 0;
        self.put_u16(self.len + 1, Type::OPT.0);
        self.put_u16(self.len + 3, udp_size);
        let ttl = ((extended_rcode as u32) << 24) | ((version as u32) << 16) | flags as u32;
        self.put_u32(self.len + 5, ttl);
        self.put_u16(self.len + 9, options_wire.len() as u16);
        self.buffer[start..end].copy_from_slice(options_wire);
        self.opt_written = true;
        self.complete(3, end);
        Ok(())
    }

    fn check_section(&self, section: u8) -> Result<(), Error> {
        if section < self.section {
            return Err(Error::new(ErrorKind::InvalidSection, self.len));
        }
        if self.counts[section as usize] == u16::MAX {
            return Err(Error::new(
                ErrorKind::CountOverflow,
                4 + section as usize * 2,
            ));
        }
        Ok(())
    }

    fn complete(&mut self, section: u8, end: usize) {
        self.counts[section as usize] += 1;
        self.put_u16(4 + section as usize * 2, self.counts[section as usize]);
        self.section = section;
        self.len = end;
    }

    fn reserve(&self, end: usize) -> Result<(), Error> {
        if end > u16::MAX as usize {
            return Err(Error::new(ErrorKind::MessageTooLong, self.len));
        }
        if end > self.buffer.len() {
            return Err(Error::new(
                ErrorKind::BufferTooSmall { needed: end },
                self.buffer.len(),
            ));
        }
        Ok(())
    }

    fn put_u16(&mut self, offset: usize, value: u16) {
        self.buffer[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn put_u32(&mut self, offset: usize, value: u32) {
        self.buffer[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn plan_name(
        &self,
        name: Name<'_>,
        offset: usize,
        earlier: &[&NamePlan],
        allow_compression: bool,
    ) -> Result<NamePlan, Error> {
        let mut plan = NamePlan::EMPTY;
        plan.len = name.write_uncompressed(&mut plan.wire)?;
        plan.prefix = plan.len;
        plan.offset = offset;
        if allow_compression && !self.table.is_empty() {
            let mut start = 0;
            while plan.wire[start] != 0 {
                let suffix = &plan.wire[start..plan.len];
                // A pointer never enlarges a name: root-only suffixes are skipped.
                if suffix.len() > 2 {
                    let hash = suffix_hash(suffix);
                    let entry = self.table[hash as usize % self.table.len()];
                    let candidate = entry.offset as usize;
                    if entry.len as usize == suffix.len()
                        && entry.hash == hash
                        && candidate + suffix.len() <= self.len
                        && self.buffer[candidate..candidate + suffix.len()] == *suffix
                    {
                        plan.prefix = start;
                        plan.pointer = Some(entry.offset);
                        return Ok(plan);
                    }
                    for previous in earlier {
                        if let Some(target) = previous.find_suffix(suffix) {
                            plan.prefix = start;
                            plan.pointer = Some(target);
                            return Ok(plan);
                        }
                    }
                }
                start += plan.wire[start] as usize + 1;
            }
        }
        Ok(plan)
    }

    fn write_name(&mut self, plan: &NamePlan) {
        let tail = plan.offset + plan.prefix;
        self.buffer[plan.offset..tail].copy_from_slice(&plan.wire[..plan.prefix]);
        if let Some(pointer) = plan.pointer {
            self.put_u16(tail, pointer | 0xc000);
        }
    }

    fn register_name(&mut self, plan: &NamePlan) {
        if self.table.is_empty() || plan.len == 0 || plan.pointer.is_some() {
            return;
        }
        let mut start = 0;
        while plan.wire[start] != 0 {
            let offset = plan.offset + start;
            if offset >= 0x4000 {
                break;
            }
            let suffix = &plan.wire[start..plan.len];
            let hash = suffix_hash(suffix);
            let slot = hash as usize % self.table.len();
            self.table[slot] = CompressionEntry {
                hash,
                offset: offset as u16,
                len: suffix.len() as u8,
            };
            start += plan.wire[start] as usize + 1;
        }
    }
}

struct NamePlan {
    wire: [u8; 255],
    len: usize,
    prefix: usize,
    pointer: Option<u16>,
    offset: usize,
}

impl NamePlan {
    const EMPTY: Self = Self {
        wire: [0; 255],
        len: 0,
        prefix: 0,
        pointer: None,
        offset: 0,
    };

    fn encoded_len(&self) -> usize {
        self.prefix + if self.pointer.is_some() { 2 } else { 0 }
    }

    fn find_suffix(&self, suffix: &[u8]) -> Option<u16> {
        if self.pointer.is_some() || self.len < suffix.len() {
            return None;
        }
        let target = self.len - suffix.len();
        let absolute = self.offset + target;
        if absolute >= 0x4000 || self.wire[target..self.len] != *suffix {
            return None;
        }
        let mut start = 0;
        while start < target {
            start += self.wire[start] as usize + 1;
        }
        (start == target).then_some(absolute as u16)
    }
}

fn section_index(section: Section) -> u8 {
    match section {
        Section::Answer => 1,
        Section::Authority => 2,
        Section::Additional => 3,
    }
}

fn known_type(rr_type: Type) -> bool {
    matches!(rr_type.0, 1 | 2 | 5 | 6 | 12 | 15 | 16 | 28 | 33 | 41 | 257)
}

fn checked_add(a: usize, b: usize, offset: usize) -> Result<usize, Error> {
    a.checked_add(b)
        .ok_or_else(|| Error::new(ErrorKind::LengthOverflow, offset))
}

fn suffix_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

fn validate_txt(wire: &[u8], offset: usize) -> Result<(), Error> {
    if wire.is_empty() {
        return Err(Error::new(ErrorKind::InvalidRdata, offset));
    }
    let mut pos = 0;
    while pos < wire.len() {
        let end = checked_add(pos, wire[pos] as usize + 1, offset)?;
        if end > wire.len() {
            return Err(Error::new(ErrorKind::InvalidRdata, offset + pos));
        }
        pos = end;
    }
    Ok(())
}

fn validate_options(wire: &[u8], offset: usize) -> Result<(), Error> {
    let mut pos = 0;
    while pos < wire.len() {
        if wire.len() - pos < 4 {
            return Err(Error::new(ErrorKind::InvalidOpt, offset + pos));
        }
        let len = u16::from_be_bytes([wire[pos + 2], wire[pos + 3]]) as usize;
        let end = checked_add(pos, 4 + len, offset)?;
        if end > wire.len() {
            return Err(Error::new(ErrorKind::InvalidOpt, offset + pos + 2));
        }
        pos = end;
    }
    Ok(())
}
