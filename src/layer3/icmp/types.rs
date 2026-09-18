//! ICMP message types: the Type byte that every ICMP message starts with,
//! and the dispatcher that decides what the rest of the bytes mean.
//!
//! Registry: <https://www.iana.org/assignments/icmp-parameters/>

use std::fmt;

/// The 8-bit Type field: what kind of ICMP message this is.
///
/// The Type is the whole dispatch: only after reading it does the
/// parser know what shape the rest of the message has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    /// Echo Reply (type 0) — a ping response.
    EchoReply,
    /// Echo Request (type 8) — a ping.
    EchoRequest,
    /// A type not yet mapped by this parser; carries the raw value.
    Unknown(u8),
}

impl From<u8> for IcmpType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::EchoReply,
            8 => Self::EchoRequest,
            x => Self::Unknown(x),
        }
    }
}

impl IcmpType {
    /// Returns the raw 8-bit type value.
    #[must_use]
    pub fn value(self) -> u8 {
        match self {
            Self::EchoReply => 0,
            Self::EchoRequest => 8,
            Self::Unknown(x) => x,
        }
    }
}

impl fmt::Display for IcmpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EchoReply => write!(f, "Echo (ping) reply"),
            Self::EchoRequest => write!(f, "Echo (ping) request"),
            Self::Unknown(_) => write!(f, "Unknown"),
        }
    }
}
