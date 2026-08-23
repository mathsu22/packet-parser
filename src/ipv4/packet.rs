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
    flags::IpFlags,
};
use std::fmt;

// Minimum number of bytes required to parse the fields implemented so far.
const MIN_PARSE_LENGTH: usize = 8;

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
    pub flags: IpFlags,
    pub fragment_offset: u16,
}

impl Ipv4Header {
    /// Parses an IPv4 header from its raw bytes.
    pub fn parse(buf: &[u8]) -> Result<Self, Ipv4Error> {
        if buf.len() < MIN_PARSE_LENGTH {
            return Err(Ipv4Error::InvalidBufferLength {
                expected: MIN_PARSE_LENGTH,
                got: buf.len(),
            });
        }

        // RFC 6274, Section 3: IPv4 Header Format.
        //
        //  Byte 0 — version (4 bits) + IHL (4 bits)
        //
        //  version lives in the 4 most significant bits of the byte.
        //  ihl lives in the 4 least significant bits.
        let b0 = buf[0];

        // Right shift (>>) pushes the bits we care about down into the low position.
        // Example: b0 in hex = 0x45, in binary = 01000101
        // Split into nibbles: 0100 0101
        // 0100 = 4 (version), 0101 = 5 (ihl)
        // '>> 4' moves every bit 4 positions to the right.
        // before: 0100 0101
        // after:  0000 0100
        // The 4 low (rightmost) bits get "dropped off the edge", and the 4 high bits
        // slide down to take their place — landing on 0000 0100, which is 4 (IPv4 version).
        let version = b0 >> 4;
        if version != IPV4_VERSION {
            return Err(Ipv4Error::InvalidVersion(version));
        }

        // `0x0F` is the hexadecimal (base 16) representation of a number.
        // `0F` corresponds to 15 in decimal.
        // Conversions: Hex: `0x0F`, Decimal: `15`, Binary: `00001111`
        // Hex values are commonly used for bitwise operations and are called "bitmasks".
        // A bitmask represents a set of bits you want to keep, clear, or check.
        // Each hex digit maps to exactly **4 bits**, which is why bitmasks are
        // usually easier to write and read in hex than in decimal.
        // b0 = 0100 0101
        // ihl is 0101, the 4 low bits — we need to isolate them.
        // The '&' operator compares bit by bit: the result at each position is 1
        // only if both bits being compared are 1. Since 0x0F = 0000(0) 1111(F),
        // the 4 high bits are always cleared (any bit & 0 = 0), and the 4 low bits
        // pass through unchanged (any bit & 1 = the bit itself). That's how the
        // mask "filters out" just the IHL bits: 0101 = 5.

        let ihl = b0 & 0x0F;
        if ihl < MIN_IHL_VALUE {
            return Err(Ipv4Error::InvalidIhl(ihl));
        }

        //  Byte 1 — DSCP (6 bits) + ECN (2 bits)
        //
        //  Same mechanics as byte 0: shift + mask, just different widths.
        let b1 = buf[1];

        // 6 most significant bits
        let dscp = b1 >> 2;

        // 2 least significant bits
        let ecn = b1 & 0x03;

        //  Bytes 2..=3 — total_length (16 bits, big-endian)
        //
        //  NETWORK HEADERS ARE BIG-ENDIAN. Always.
        //  from_be_bytes builds a u16 treating the first byte as the high byte.
        let total_length = u16::from_be_bytes([buf[2], buf[3]]);

        // Bytes 4..=5 — identification (16 bits, big-endian)
        let identification = u16::from_be_bytes([buf[4], buf[5]]);

        //  Bytes 6..=7 — flags (3 bits) + fragment_offset (13 bits)
        let word = u16::from_be_bytes([buf[6], buf[7]]);

        // shift >> 13 to isolate the flags (3 bits)
        let raw_flags = (word >> 13) as u8;
        let flags = IpFlags::parse(raw_flags);

        // & 0x1FFF to isolate the fragment offset (13 bits)
        let fragment_offset = word & 0x1FFF;

        Ok(Self {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
        })
    }
}

// Output formatting inspired by Wireshark.
impl fmt::Display for Ipv4Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reserved_warning = if self.flags.is_anomalous() {
            "- [Expert Info (Warning/Protocol): Reserved bit is set (must be zero)]"
        } else {
            ""
        };

        write!(
            f,
            "\
            Version: {} \n\
            Header Length: {} bytes ({}) \n\
            Differentiated Services Field: {:#04x} (DSCP: {}, ECN: {}) \n\
            Total Length: {} \n\
            Identification: {:#06x} ({}) \n\
            Flags: {:#04x}, {} {}\n\
            Fragment Offset: {} \n\
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
            self.flags.as_byte(),
            self.flags,
            reserved_warning,
            self.fragment_offset,
        )
    }
}
