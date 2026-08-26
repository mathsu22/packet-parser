//! Layer 3: the IPv4 packet header.
//!
//! Ethernet was a fixed 14 bytes. IPv4 is *variable length*: the header is
//! normally 20 bytes but can carry up to 40 bytes of options. You don't know
//! where the payload begins until you read the **IHL** field. Get that wrong
//! and every layer above it decodes garbage — or you read out of bounds. So
//! this is where careful, length-driven parsing really starts to matter.

use crate::ipv4::{errors::Ipv4Error, flags::IpFlags, protocol::IpProtocol};
use std::net::Ipv4Addr;

// IPv4 IHL is expressed in 32-bit words.
// 5 words × 4 bytes = 20 bytes minimum.
const MIN_HEADER_LENGTH: usize = 20;

const MIN_IHL_VALUE: u8 = 5;
const IPV4_VERSION: u8 = 4;

/// Represents the decoded fields of an IPv4 packet header.
pub struct Ipv4Header {
    /// IP version. Always 4 for this parser (enforced during `parse`).
    pub version: u8,
    /// Internet Header Length, in 32-bit words (minimum 5 = 20 bytes).
    pub ihl: u8,
    /// Differentiated Services Code Point (6 bits of the DS field).
    pub dscp: u8,
    /// Explicit Congestion Notification (2 bits of the DS field).
    pub ecn: u8,
    /// Total length of the IP packet (header + payload), in bytes.
    pub total_length: u16,
    /// Identifies fragments belonging to the same original datagram.
    pub identification: u16,
    /// The 3-bit control flags (reserved, don't-fragment, more-fragments).
    pub flags: IpFlags,
    /// Offset of this fragment within the original datagram, in 8-byte units.
    pub fragment_offset: u16,
    /// Time to Live: max hops before the packet is discarded.
    pub ttl: u8,
    /// The payload protocol (ICMP, TCP, UDP, or unknown).
    pub protocol: IpProtocol,
    /// Header checksum, for error-checking the header only.
    pub checksum: u16,
    /// Source IPv4 address.
    pub source_address: Ipv4Addr,
    /// Destination IPv4 address.
    pub destination_address: Ipv4Addr,
}

impl Ipv4Header {
    /// Parses an IPv4 header from its raw bytes.
    pub fn parse(buf: &[u8]) -> Result<Self, Ipv4Error> {
        if buf.len() < MIN_HEADER_LENGTH {
            return Err(Ipv4Error::InvalidBufferLength {
                expected: MIN_HEADER_LENGTH,
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

        //  BYTES 8..=11 — TTL, protocol, header checksum
        let ttl = buf[8];
        let protocol = IpProtocol::from(buf[9]);
        let checksum = u16::from_be_bytes([buf[10], buf[11]]);

        //  BYTES 12..=15 — source IP
        let source_address = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        //  BYTES 16..=19 — destination IP
        let destination_address = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

        Ok(Self {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            source_address,
            destination_address,
        })
    }
}
