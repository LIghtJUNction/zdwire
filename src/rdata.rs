use crate::{u16_at, u32_at, Error, ErrorKind, Name, Record, Section, Type};
use core::iter::FusedIterator;

/// Typed, borrowed RDATA for the supported DNS wire formats.
#[derive(Clone, Copy, Debug)]
pub enum Rdata<'a> {
    /// IPv4 address octets in network order.
    A(&'a [u8; 4]),
    /// IPv6 address octets in network order.
    Aaaa(&'a [u8; 16]),
    /// Authoritative server name.
    Ns(Name<'a>),
    /// Canonical name.
    Cname(Name<'a>),
    /// Domain-name pointer.
    Ptr(Name<'a>),
    /// Mail exchange.
    Mx {
        /// Preference (lower values are preferred).
        preference: u16,
        /// Exchange name.
        exchange: Name<'a>,
    },
    /// One or more length-prefixed character strings.
    Txt(Txt<'a>),
    /// Start of authority.
    Soa {
        /// Primary master name.
        mname: Name<'a>,
        /// Responsible mailbox as a DNS name.
        rname: Name<'a>,
        /// Zone serial number.
        serial: u32,
        /// Refresh interval.
        refresh: u32,
        /// Retry interval.
        retry: u32,
        /// Expiry interval.
        expire: u32,
        /// Minimum/negative-cache TTL.
        minimum: u32,
    },
    /// Service endpoint. RFC 2782 forbids compression in its target field.
    Srv {
        /// Priority.
        priority: u16,
        /// Weight.
        weight: u16,
        /// Port.
        port: u16,
        /// Uncompressed target name.
        target: Name<'a>,
    },
    /// Certificate authority authorization (wire syntax only).
    Caa {
        /// Property flags, including unrecognized bits.
        flags: u8,
        /// ASCII alphanumeric property tag (1..=255 bytes).
        tag: &'a [u8],
        /// Uninterpreted property value.
        value: &'a [u8],
    },
    /// EDNS control information and validated option tuples.
    Opt(Opt<'a>),
    /// An unsupported RR type, preserved byte-for-byte.
    Unknown {
        /// Original type code.
        rr_type: Type,
        /// Opaque original data; do not relocate legacy compressed data blindly.
        rdata: &'a [u8],
    },
}

impl<'a> Rdata<'a> {
    pub(crate) fn parse(record: Record<'a>) -> Result<Self, Error> {
        let data = record.rdata;
        let offset = record.rdata_offset();
        // Record fields are public. Reject a replaced RDATA slice before using
        // its length as a bound into the original message's compression space.
        if offset > record.message.len()
            || data.len() > record.message.len() - offset
            || data.as_ptr() != record.message[offset..].as_ptr()
        {
            return Err(Error::new(ErrorKind::InvalidRdata, offset));
        }
        let end = offset + data.len();
        let invalid = || Error::new(ErrorKind::InvalidRdata, offset);
        let field_u16 = |pos| u16_at(data, pos).map_err(|e| Error::new(e.kind, offset + e.offset));
        let field_u32 = |pos| u32_at(data, pos).map_err(|e| Error::new(e.kind, offset + e.offset));
        let name_at = |pos, compression| Name::parse_bounded(record.message, pos, end, compression);
        let exact = |actual| {
            if actual == end {
                Ok(())
            } else {
                Err(Error::new(ErrorKind::InvalidRdata, actual))
            }
        };
        Ok(match record.rr_type {
            Type::A => Self::A(data.try_into().map_err(|_| invalid())?),
            Type::AAAA => Self::Aaaa(data.try_into().map_err(|_| invalid())?),
            Type::NS | Type::CNAME | Type::PTR => {
                let (name, consumed) = name_at(offset, true)?;
                exact(consumed)?;
                match record.rr_type {
                    Type::NS => Self::Ns(name),
                    Type::CNAME => Self::Cname(name),
                    _ => Self::Ptr(name),
                }
            }
            Type::MX => {
                let preference = field_u16(0)?;
                let (exchange, consumed) = name_at(offset + 2, true)?;
                exact(consumed)?;
                Self::Mx {
                    preference,
                    exchange,
                }
            }
            Type::TXT => Self::Txt(Txt::parse_at(data, offset)?),
            Type::SOA => {
                let (mname, next) = name_at(offset, true)?;
                let (rname, next) = name_at(next, true)?;
                if end - next != 20 {
                    return Err(Error::new(ErrorKind::InvalidRdata, next));
                }
                let base = next - offset;
                Self::Soa {
                    mname,
                    rname,
                    serial: field_u32(base)?,
                    refresh: field_u32(base + 4)?,
                    retry: field_u32(base + 8)?,
                    expire: field_u32(base + 12)?,
                    minimum: field_u32(base + 16)?,
                }
            }
            Type::SRV => {
                let priority = field_u16(0)?;
                let weight = field_u16(2)?;
                let port = field_u16(4)?;
                let (target, consumed) = name_at(offset + 6, false)?;
                exact(consumed)?;
                Self::Srv {
                    priority,
                    weight,
                    port,
                    target,
                }
            }
            Type::CAA => {
                if data.len() < 2 {
                    return Err(Error::new(ErrorKind::UnexpectedEnd, end));
                }
                let len = data[1] as usize;
                if len == 0 {
                    return Err(Error::new(ErrorKind::InvalidRdata, offset + 1));
                }
                if len > data.len() - 2 {
                    return Err(Error::new(ErrorKind::UnexpectedEnd, end));
                }
                let tag = &data[2..2 + len];
                if let Some(pos) = tag.iter().position(|byte| !byte.is_ascii_alphanumeric()) {
                    return Err(Error::new(ErrorKind::InvalidRdata, offset + 2 + pos));
                }
                Self::Caa {
                    flags: data[0],
                    tag,
                    value: &data[2 + len..],
                }
            }
            Type::OPT => {
                if record.section != Section::Additional
                    || !record.name.is_root()
                    || record.name.encoded_len() != 1
                {
                    return Err(Error::new(ErrorKind::InvalidOpt, record.name.offset()));
                }
                validate_options(data, offset)?;
                Self::Opt(Opt {
                    udp_payload_size: record.class.0,
                    ttl: record.ttl,
                    data,
                })
            }
            rr_type => Self::Unknown {
                rr_type,
                rdata: data,
            },
        })
    }
}

/// Validated TXT wire data. Strings remain separate, and may contain any octet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Txt<'a> {
    data: &'a [u8],
}
impl<'a> Txt<'a> {
    /// Validates standalone length-prefixed character strings.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() > u16::MAX as usize {
            return Err(Error::new(ErrorKind::InvalidRdata, u16::MAX as usize));
        }
        Self::parse_at(data, 0)
    }
    fn parse_at(data: &'a [u8], base: usize) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::new(ErrorKind::InvalidRdata, base));
        }
        let mut pos = 0;
        while pos < data.len() {
            let len = data[pos] as usize;
            pos += 1;
            if len > data.len() - pos {
                return Err(Error::new(ErrorKind::UnexpectedEnd, base + data.len()));
            }
            pos += len;
        }
        Ok(Self { data })
    }
    /// Exact original, length-prefixed wire bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.data
    }
    /// Iterates borrowed character-string contents, without their lengths.
    pub fn iter(self) -> TxtIter<'a> {
        TxtIter {
            remaining: self.data,
        }
    }
}

/// Iterator over validated TXT strings.
#[derive(Clone, Debug)]
pub struct TxtIter<'a> {
    remaining: &'a [u8],
}
impl<'a> Iterator for TxtIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        let (&len, bytes) = self.remaining.split_first()?;
        let (string, rest) = bytes.split_at(len as usize);
        self.remaining = rest;
        Some(string)
    }
}
impl FusedIterator for TxtIter<'_> {}

/// Basic EDNS OPT information. Unknown versions, flags, and options are retained.
#[derive(Clone, Copy, Debug)]
pub struct Opt<'a> {
    udp_payload_size: u16,
    ttl: u32,
    data: &'a [u8],
}
impl<'a> Opt<'a> {
    /// Advertised UDP payload size, without resolver policy adjustment.
    pub const fn udp_payload_size(self) -> u16 {
        self.udp_payload_size
    }
    /// Upper eight bits of the twelve-bit response code.
    pub const fn extended_rcode(self) -> u8 {
        (self.ttl >> 24) as u8
    }
    /// Advertised EDNS version.
    pub const fn version(self) -> u8 {
        (self.ttl >> 16) as u8
    }
    /// EDNS flag field, including reserved bits.
    pub const fn flags(self) -> u16 {
        self.ttl as u16
    }
    /// DO bit; indicates DNSSEC capability, not successful authentication.
    pub const fn dnssec_ok(self) -> bool {
        self.flags() & 0x8000 != 0
    }
    /// Combines EDNS extended response code and a DNS header's base code.
    pub const fn full_rcode(self, base: u8) -> u16 {
        ((self.extended_rcode() as u16) << 4) | (base as u16 & 0x0f)
    }
    /// Exact original option wire data.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.data
    }
    /// Iterates validated option tuples; no option-specific interpretation.
    pub fn options(self) -> OptOptions<'a> {
        OptOptions {
            remaining: self.data,
        }
    }
}

/// An EDNS option, including unknown option codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OptOption<'a> {
    /// Option code.
    pub code: u16,
    /// Option payload, excluding code and length.
    pub data: &'a [u8],
}

/// Iterator over a prevalidated EDNS option sequence.
#[derive(Clone, Debug)]
pub struct OptOptions<'a> {
    remaining: &'a [u8],
}
impl<'a> OptOptions<'a> {
    /// Validates standalone EDNS option wire bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() > u16::MAX as usize {
            return Err(Error::new(ErrorKind::InvalidOpt, u16::MAX as usize));
        }
        validate_options(data, 0)?;
        Ok(Self { remaining: data })
    }
}
impl<'a> Iterator for OptOptions<'a> {
    type Item = OptOption<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let b = self.remaining;
        let code = u16::from_be_bytes([b[0], b[1]]);
        let len = u16::from_be_bytes([b[2], b[3]]) as usize;
        self.remaining = &b[4 + len..];
        Some(OptOption {
            code,
            data: &b[4..4 + len],
        })
    }
}
impl FusedIterator for OptOptions<'_> {}

fn validate_options(data: &[u8], base: usize) -> Result<(), Error> {
    let mut pos = 0;
    while pos < data.len() {
        if data.len() - pos < 4 {
            return Err(Error::new(ErrorKind::InvalidOpt, base + data.len()));
        }
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if len > data.len() - pos {
            return Err(Error::new(ErrorKind::InvalidOpt, base + data.len()));
        }
        pos += len;
    }
    Ok(())
}
