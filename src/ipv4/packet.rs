//! Layer 3: the IPv4 packet header.
//!
//! Ethernet was a fixed 14 bytes. IPv4 is *variable length*: the header is
//! normally 20 bytes but can carry up to 40 bytes of options. You don't know
//! where the payload begins until you read the **IHL** field. Get that wrong
//! and every layer above it decodes garbage — or you read out of bounds. So
//! this is where careful, length-driven parsing really starts to matter.

use crate::ipv4::{
    dscp_ecn::{dscp_name, ecn_keyword},
    errors::Ipv4Error,
};
use std::fmt;

// Minimum number of bytes required to parse the fields implemented so far.
const MIN_PARSE_LENGTH: usize = 6;

// IPv4 IHL is expressed in 32-bit words.
// 5 words × 4 bytes = 20 bytes minimum.
//const MIN_HEADER_LENGTH: usize = 20;

const MIN_IHL_VALUE: u8 = 5;
const IPV4_VERSION: u8 = 4;

pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
}

impl Ipv4Header {
    pub fn parse(buf: &[u8]) -> Result<Self, Ipv4Error> {
        if buf.len() < MIN_PARSE_LENGTH {
            return Err(Ipv4Error::InvalidBufferLength {
                expected: MIN_PARSE_LENGTH,
                got: buf.len(),
            });
        }

        // RFC 6274, Section 3: IPv4 Header Format.
        // Version and IHL share the first byte.
        let b0 = buf[0];

        // Version occupies the 4 most significant bits.
        let version = b0 >> 4;
        if version != IPV4_VERSION {
            return Err(Ipv4Error::InvalidVersion(version));
        }
        // IHL occupies the 4 least significant bits.
        let ihl = b0 & 0x0F;
        if ihl < MIN_IHL_VALUE {
            return Err(Ipv4Error::InvalidIhl(ihl));
        }

        // DSCP occupies the 6 most significant bits of the second byte.
        let b1 = buf[1];
        let dscp = b1 >> 2;

        // ECN occupies the 2 least significant bits.
        let ecn = b1 & 0x03;

        // Total Length is a 16-bit big-endian field.
        let total_length = u16::from_be_bytes([buf[2], buf[3]]);

        // Identification is a 16-bit big-endian field.
        let identification = u16::from_be_bytes([buf[4], buf[5]]);

        Ok(Self {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
        })
    }
}

// Output formatting inspired by Wireshark.
impl fmt::Display for Ipv4Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\
            Version: {} \n\
            Header Length: {} bytes ({}) \n\
            Differentiated Services Field: {:#04x} (DSCP: {}, ECN: {}) \n\
            Total Length: {} \n\
            Identification: {:#06x} ({}) \n\
            ",
            self.version,
            self.ihl * 4,
            self.ihl,
            (self.dscp << 2) | self.ecn,
            dscp_name(self.dscp),
            ecn_keyword(self.ecn),
            self.total_length,
            self.identification,
            self.identification,
        )
    }
}
