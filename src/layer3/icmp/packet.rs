//! ICMP (Internet Control Message Protocol) dissector
//!
//! Unlike IPv4, ICMP has no length field of its own and no fixed body
//! shape: only the first 4 bytes (Type, Code, Checksum) mean the same
//! thing for every message. What comes after depends entirely on the Type.

use crate::{checksum::ChecksumStatus, layer3::icmp::types::IcmpType};

/// The body of an Echo Request/Reply message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpEcho {
    /// Identifies which `ping` session this message belongs to.
    pub identifier: u16,
    /// Incremented on each Echo Request sent, so replies can be matched
    /// to requests and reordering/loss can be detected.
    pub sequence_number: u16,
}

/// The type-specific body of an ICMP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpMessage {
    /// Echo Request or Echo Reply body.
    Echo(IcmpEcho),
    /// A type not yet mapped by this parser.
    Other,
}

/// The decoded fields of an ICMP message.
#[derive(Debug)]
pub struct IcmpHeader {
    /// What kind of ICMP message this is.
    pub type_: IcmpType,
    /// Sub-classifies the Type.
    pub code: u8,
    /// Checksum covering the entire ICMP message (header + data).
    pub checksum: u16,
    /// Whether the checksum verified during `parse`.
    pub checksum_status: ChecksumStatus,
    /// The type-specific body.
    pub message: IcmpMessage,
}
