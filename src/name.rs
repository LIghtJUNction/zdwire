use crate::{Error, ErrorKind, MAX_MESSAGE_LEN};
use core::{fmt, iter::FusedIterator};

/// Maximum uncompressed DNS name size, including label lengths and root.
pub const MAX_NAME_LEN: usize = 255;
/// Maximum compression pointers followed while validating one name.
pub const MAX_POINTER_HOPS: usize = 32;

/// A validated, zero-copy name whose compression targets borrow the same packet.
///
/// Labels are arbitrary octets. Equality folds ASCII letters only, as required
/// by DNS; display uses decimal escapes for non-printable bytes and escapes dots
/// and backslashes. Iterators omit the terminating empty root label.
#[derive(Clone, Copy, Debug)]
pub struct Name<'a> {
    message: &'a [u8],
    start: u16,
    end: u16,
    labels_start: u16,
    expanded_len: u16,
}

impl<'a> Name<'a> {
    /// Parses a name at an absolute packet offset and returns the byte after its
    /// original encoded representation. Compression pointers must go backward.
    pub fn parse(message: &'a [u8], offset: usize) -> Result<(Self, usize), Error> {
        if message.len() > MAX_MESSAGE_LEN {
            return Err(Error::new(ErrorKind::MessageTooLong, MAX_MESSAGE_LEN));
        }
        Self::parse_bounded(message, offset, message.len(), true)
    }

    /// Validates an exact, uncompressed wire name, including its final zero.
    pub fn from_wire(wire: &'a [u8]) -> Result<Self, Error> {
        if wire.len() > MAX_NAME_LEN {
            return Err(Error::new(ErrorKind::NameTooLong, MAX_NAME_LEN));
        }
        let (name, end) = Self::parse_bounded(wire, 0, wire.len(), false)?;
        if end != wire.len() {
            return Err(Error::new(ErrorKind::TrailingData, end));
        }
        Ok(name)
    }

    #[inline]
    pub(crate) fn parse_bounded(
        message: &'a [u8],
        start: usize,
        limit: usize,
        compression: bool,
    ) -> Result<(Self, usize), Error> {
        let mut pos = start;
        let mut expanded = 1usize;
        loop {
            if pos >= limit {
                return Err(Error::new(ErrorKind::UnexpectedEnd, limit));
            }
            let len = message[pos] as usize;
            if len == 0 {
                return Ok((
                    Self {
                        message,
                        start: start as u16,
                        end: (pos + 1) as u16,
                        labels_start: start as u16,
                        expanded_len: expanded as u16,
                    },
                    pos + 1,
                ));
            }
            if len >= 0xc0 {
                if !compression {
                    return Err(Error::new(ErrorKind::InvalidRdata, pos));
                }
                return Self::compressed(message, start, pos, limit, expanded);
            }
            if len >= 64 {
                return Err(Error::new(ErrorKind::InvalidLabelType, pos));
            }
            if len > limit - pos - 1 {
                return Err(Error::new(ErrorKind::UnexpectedEnd, limit));
            }
            expanded += len + 1;
            if expanded > MAX_NAME_LEN {
                return Err(Error::new(ErrorKind::NameTooLong, pos));
            }
            pos += len + 1;
        }
    }

    fn compressed(
        message: &'a [u8],
        start: usize,
        mut pos: usize,
        limit: usize,
        mut expanded: usize,
    ) -> Result<(Self, usize), Error> {
        if limit - pos < 2 {
            return Err(Error::new(ErrorKind::UnexpectedEnd, limit));
        }
        let end = pos + 2;
        let mut seen = [0u16; MAX_POINTER_HOPS];
        let mut hops = 0;
        let mut first = if start == pos { None } else { Some(start) };
        loop {
            // Every pointer is checked before following it. Literal runs are
            // bounded by the input length and the expanded-name length.
            let len = *message
                .get(pos)
                .ok_or(Error::new(ErrorKind::UnexpectedEnd, message.len()))?
                as usize;
            if len >= 0xc0 {
                let low = *message
                    .get(pos + 1)
                    .ok_or(Error::new(ErrorKind::UnexpectedEnd, message.len()))?
                    as usize;
                let target = ((len & 0x3f) << 8) | low;
                if target >= message.len() {
                    return Err(Error::new(ErrorKind::PointerOutOfBounds, pos));
                }
                if target == pos || seen[..hops].contains(&(pos as u16)) {
                    return Err(Error::new(ErrorKind::PointerLoop, pos));
                }
                if target > pos {
                    return Err(Error::new(ErrorKind::ForwardPointer, pos));
                }
                if hops == MAX_POINTER_HOPS {
                    return Err(Error::new(ErrorKind::PointerLimit, pos));
                }
                seen[hops] = pos as u16;
                hops += 1;
                pos = target;
                continue;
            }
            let first = *first.get_or_insert(pos);
            if len == 0 {
                return Ok((
                    Self {
                        message,
                        start: start as u16,
                        end: end as u16,
                        labels_start: first as u16,
                        expanded_len: expanded as u16,
                    },
                    end,
                ));
            }
            if len >= 64 {
                return Err(Error::new(ErrorKind::InvalidLabelType, pos));
            }
            if len > message.len() - pos - 1 {
                return Err(Error::new(ErrorKind::UnexpectedEnd, message.len()));
            }
            expanded += len + 1;
            if expanded > MAX_NAME_LEN {
                return Err(Error::new(ErrorKind::NameTooLong, pos));
            }
            pos += len + 1;
        }
    }

    /// Iterates borrowed labels, excluding the root. Validation is not repeated.
    #[inline]
    pub fn labels(self) -> Labels<'a> {
        Labels {
            message: self.message,
            pos: self.labels_start as usize,
            done: false,
        }
    }

    /// Absolute offset of this name's encoded representation.
    pub const fn offset(self) -> usize {
        self.start as usize
    }

    /// Length of the uncompressed wire representation, including the root.
    pub const fn wire_len(self) -> usize {
        self.expanded_len as usize
    }

    /// Length occupied in the original packet, including a terminating pointer.
    pub const fn encoded_len(self) -> usize {
        (self.end - self.start) as usize
    }

    /// Whether the encoded name contains a compression pointer.
    pub const fn is_compressed(self) -> bool {
        self.encoded_len() != self.wire_len()
    }

    /// Whether this is the root name.
    pub const fn is_root(self) -> bool {
        self.expanded_len == 1
    }

    /// Writes the expanded wire representation. On insufficient capacity, leaves
    /// the output untouched and returns the exact required length.
    pub fn write_uncompressed(self, output: &mut [u8]) -> Result<usize, Error> {
        let needed = self.wire_len();
        if output.len() < needed {
            return Err(Error::new(
                ErrorKind::BufferTooSmall { needed },
                output.len(),
            ));
        }
        let mut pos = 0;
        for label in self.labels() {
            output[pos] = label.len() as u8;
            pos += 1;
            output[pos..pos + label.len()].copy_from_slice(label);
            pos += label.len();
        }
        output[pos] = 0;
        Ok(needed)
    }

    /// Compares original label octets without DNS case folding.
    pub fn eq_case_sensitive(self, other: Self) -> bool {
        self.labels().eq(other.labels())
    }
}

impl PartialEq for Name<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.wire_len() == other.wire_len()
            && self
                .labels()
                .zip(other.labels())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}
impl Eq for Name<'_> {}

impl fmt::Display for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for label in self.labels() {
            for &byte in label {
                match byte {
                    b'.' | b'\\' => write!(f, "\\{}", byte as char)?,
                    b'!'..=b'~' => write!(f, "{}", byte as char)?,
                    _ => write!(f, "\\{byte:03}")?,
                }
            }
            f.write_str(".")?;
        }
        if self.is_root() {
            f.write_str(".")?;
        }
        Ok(())
    }
}

/// Iterator over a validated name's borrowed, non-root labels.
#[derive(Clone, Debug)]
pub struct Labels<'a> {
    message: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            let len = self.message[self.pos] as usize;
            if len == 0 {
                self.done = true;
                return None;
            }
            if len >= 0xc0 {
                self.pos = ((len & 0x3f) << 8) | self.message[self.pos + 1] as usize;
                continue;
            }
            let start = self.pos + 1;
            self.pos = start + len;
            return Some(&self.message[start..self.pos]);
        }
    }
}
impl FusedIterator for Labels<'_> {}

/// Encodes a textual name into uncompressed wire form, without allocation.
///
/// Accepts an optional final dot, `\\.` / `\\\\`, and `\\DDD` decimal octets.
/// UTF-8 is copied as bytes; IDNA conversion is deliberately outside this crate.
/// The empty string and `"."` denote root. Failure leaves `output` untouched.
/// Text errors report offsets into `text`; capacity errors report output length.
pub fn encode_name(text: &str, output: &mut [u8]) -> Result<usize, Error> {
    let bytes = text.as_bytes();
    let mut wire = [0u8; MAX_NAME_LEN];
    if bytes.is_empty() || bytes == b"." {
        if output.is_empty() {
            return Err(Error::new(ErrorKind::BufferTooSmall { needed: 1 }, 0));
        }
        output[0] = 0;
        return Ok(1);
    }
    let mut input = 0;
    let mut pos = 1;
    let mut label_at = 0;
    let mut label_len = 0usize;
    while input < bytes.len() {
        let source_at = input;
        let mut byte = bytes[input];
        input += 1;
        if byte == b'.' {
            if label_len == 0 {
                return Err(Error::new(ErrorKind::InvalidTextName, source_at));
            }
            wire[label_at] = label_len as u8;
            if input == bytes.len() {
                break;
            }
            if pos >= MAX_NAME_LEN - 1 {
                return Err(Error::new(ErrorKind::NameTooLong, source_at));
            }
            label_at = pos;
            pos += 1;
            label_len = 0;
            continue;
        }
        if byte == b'\\' {
            byte = *bytes
                .get(input)
                .ok_or(Error::new(ErrorKind::InvalidTextName, source_at))?;
            if byte.is_ascii_digit() {
                let digits = bytes
                    .get(input..input.saturating_add(3))
                    .ok_or(Error::new(ErrorKind::InvalidTextName, source_at))?;
                if !digits.iter().all(u8::is_ascii_digit) {
                    return Err(Error::new(ErrorKind::InvalidTextName, source_at));
                }
                let value = (digits[0] - b'0') as u16 * 100
                    + (digits[1] - b'0') as u16 * 10
                    + (digits[2] - b'0') as u16;
                if value > 255 {
                    return Err(Error::new(ErrorKind::InvalidTextName, source_at));
                }
                byte = value as u8;
                input += 3;
            } else {
                input += 1;
            }
        }
        if label_len == 63 {
            return Err(Error::new(ErrorKind::LabelTooLong, source_at));
        }
        if pos >= MAX_NAME_LEN - 1 {
            return Err(Error::new(ErrorKind::NameTooLong, source_at));
        }
        wire[pos] = byte;
        pos += 1;
        label_len += 1;
    }
    wire[label_at] = label_len as u8;
    wire[pos] = 0;
    let needed = pos + 1;
    if output.len() < needed {
        return Err(Error::new(
            ErrorKind::BufferTooSmall { needed },
            output.len(),
        ));
    }
    output[..needed].copy_from_slice(&wire[..needed]);
    Ok(needed)
}
