use core::fmt;

/// A wire or encoding error with an absolute byte offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    /// The exact failure category.
    pub kind: ErrorKind,
    /// Offending byte, or the first missing byte for truncated input.
    pub offset: usize,
}

impl Error {
    /// Constructs an error at `offset`.
    pub const fn new(kind: ErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }
}

/// Errors produced by DNS wire parsing and encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input ended before a field was complete.
    UnexpectedEnd,
    /// A reserved/unsupported label type (01 or 10 high bits) was found.
    InvalidLabelType,
    /// An encoded label would exceed 63 bytes.
    LabelTooLong,
    /// The expanded wire name would exceed 255 bytes including the root.
    NameTooLong,
    /// A compression target lies outside the message.
    PointerOutOfBounds,
    /// A compression pointer refers to itself or a previously visited pointer.
    PointerLoop,
    /// A compression pointer refers to a later byte, contrary to RFC 1035.
    ForwardPointer,
    /// The name exceeded the documented compression hop limit.
    PointerLimit,
    /// A known RR's data has an invalid size or field value.
    InvalidRdata,
    /// Bytes remain after an exact-length field or complete message.
    TrailingData,
    /// OPT has a non-root owner, invalid placement, or malformed option data.
    InvalidOpt,
    /// More than one OPT record occurred in the message.
    DuplicateOpt,
    /// An encoder append would violate DNS section order.
    InvalidSection,
    /// A section would contain more than 65,535 entries.
    CountOverflow,
    /// A message would exceed 65,535 bytes.
    MessageTooLong,
    /// The caller's output buffer is too small.
    BufferTooSmall {
        /// Required total buffer length for this operation.
        needed: usize,
    },
    /// An arithmetic operation or length field would overflow.
    LengthOverflow,
    /// An invalid escape or an empty interior label in a textual name.
    InvalidTextName,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} at byte {}", self.kind, self.offset)
    }
}
