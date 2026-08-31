//! IPv4 header checksum computation and verification (RFC 1071).
//!
//! The checksum is the 16-bit one's complement of the one's complement sum
//! of all 16-bit words in the header. For verification purposes, computing
//! the checksum over the entire header (including the checksum field itself)
//! should yield zero.

use std::fmt;

/// Computes the IPv4 header checksum over the given buffer.
pub fn checksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for chunk in buf.chunks(2) {
        let word = match chunk.len() {
            2 => u16::from_be_bytes([chunk[0], chunk[1]]),
            1 => u16::from(chunk[0]) << 8,
            _ => 0,
        };

        sum += u32::from(word);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Result of verifying an IPv4 header checksum.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ChecksumStatus {
    /// The sum over the header (checksum field included) is zero.
    Good,
    /// The sum is nonzero — at least one header bit is corrupted.
    Bad,
    /// Checksum could not be verified (e.g., buffer was truncated).
    NotVerifiable,
}

impl fmt::Display for ChecksumStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Good => write!(f, "correct"),
            Self::Bad => write!(f, "incorrect"),
            Self::NotVerifiable => write!(f, "unverified"),
        }
    }
}
