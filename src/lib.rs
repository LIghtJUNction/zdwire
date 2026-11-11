#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
//! Allocation-free DNS wire parsing and encoding using caller-owned buffers.
//!
//! [`MessageView::parse`] reads the header only. Iterators validate the fields
//! they traverse; [`MessageView::validate`] checks every section, supported RDATA
//! format, EDNS placement, and the end of the packet. No resolver or I/O is used.
//!
//! The message limit is 65,535 bytes, names expand to at most 255 bytes, and
//! each name may follow at most [`MAX_POINTER_HOPS`] compression pointers.
//! All errors carry an absolute byte offset into the original wire message.

mod encode;
mod error;
mod message;
mod name;
mod rdata;

pub use encode::{CompressionEntry, MessageBuilder, RecordData};
pub use error::{Error, ErrorKind};
pub use message::{
    Class, Header, MessageView, Question, Questions, Record, Records, Section, Type,
};
pub use name::{Labels, MAX_NAME_LEN, MAX_POINTER_HOPS, Name, encode_name};
pub use rdata::{Opt, OptOption, OptOptions, Rdata, Txt, TxtIter};

/// Maximum DNS message size, excluding a transport's length prefix.
pub const MAX_MESSAGE_LEN: usize = 65_535;

#[inline]
pub(crate) fn take(data: &[u8], offset: usize, len: usize) -> Result<&[u8], Error> {
    if offset > data.len() || len > data.len() - offset {
        return Err(Error::new(ErrorKind::UnexpectedEnd, data.len()));
    }
    Ok(&data[offset..offset + len])
}

#[inline]
pub(crate) fn u16_at(data: &[u8], offset: usize) -> Result<u16, Error> {
    let bytes = take(data, offset, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[inline]
pub(crate) fn u32_at(data: &[u8], offset: usize) -> Result<u32, Error> {
    let bytes = take(data, offset, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
