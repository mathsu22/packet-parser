//! Ethernet II framing: the Data Link layer (Layer 2).
//!
//! Ethernet II uses a fixed 14-byte header consisting of:
//! - 6 bytes for the destination MAC address.
//! - 6 bytes for the source MAC address.
//! - 2 bytes for the EtherType field.
//!
//! The EtherType field identifies the protocol carried in the payload,
//! such as IPv4, ARP, or IPv6.
//!
//! A real Ethernet frame may also include a 4-byte Frame Check Sequence
//! (FCS) trailer. Most capture tools, including pcap and tcpdump, do not
//! include the FCS because it is normally stripped by the network
//! interface before the frame is passed to the operating system.
//!
//! ## References
//!
//! - [IEEE 802.3-2022 – Ethernet](https://standards.ieee.org/ieee/802.3/10422/)
//! - [IANA EtherType registry](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)
//! - [RFC 894 – IP over Ethernet](https://www.rfc-editor.org/rfc/rfc894)

use std::fmt;
use thiserror::Error;

const HEADER_LENGTH: usize = 14;

/// A 6-byte Ethernet (MAC) address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [b0, b1, b2, b3, b4, b5] = self.0;
        write!(f, "{b0:02x}:{b1:02x}:{b2:02x}:{b3:02x}:{b4:02x}:{b5:02x}")
    }
}

/// The 16-bit EtherType field: what protocol the payload carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    /// IPv4 (0x0800).
    Ipv4,
    /// ARP (0x0806).
    Arp,
    /// IPv6 (0x86DD).
    Ipv6,
    /// A value not yet mapped by this parser.
    Unknown(u16),
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 => write!(f, "IPv4"),
            Self::Arp => write!(f, "ARP"),
            Self::Ipv6 => write!(f, "IPv6"),
            Self::Unknown(_) => write!(f, "Unknown"),
        }
    }
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86DD => Self::Ipv6,
            x => Self::Unknown(x),
        }
    }
}

impl EtherType {
    /// Returns the raw 16-bit EtherType value for this variant.
    pub fn value(self) -> u16 {
        match self {
            Self::Ipv4 => 0x0800,
            Self::Arp => 0x0806,
            Self::Ipv6 => 0x86DD,
            Self::Unknown(x) => x,
        }
    }
}

/// Errors that can occur while parsing an Ethernet II frame.
#[derive(Error, Debug)]
pub enum EthernetError {
    /// The provided buffer is smaller than the fixed 14-byte header.
    #[error("Buffer too short for an Ethernet header: need at least {expected} bytes, got {got}")]
    BufferTooShortForHeader {
        /// Always 14.
        expected: usize,
        /// The actual number of bytes present.
        got: usize,
    },
}

/// The decoded fields of an Ethernet II frame header.
#[derive(Debug)]
pub struct EthernetHeader {
    /// Destination MAC address.
    pub dst_mac: MacAddress,
    /// Source MAC address.
    pub src_mac: MacAddress,
    /// What Protocol the payload carries.
    pub ethertype: EtherType,
}

impl EthernetHeader {
    /// Parses an Ethernet II header from `buf`, returning the header
    /// and the remaining payload (everything after the first 14 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`EthernetError::BufferTooShortForHeader`] if `buf` is
    /// shorter than 14 bytes.
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8]), EthernetError> {
        if buf.len() < HEADER_LENGTH {
            return Err(EthernetError::BufferTooShortForHeader {
                expected: HEADER_LENGTH,
                got: buf.len(),
            });
        }

        let dst_mac = MacAddress([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]]);
        let src_mac = MacAddress([buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]]);

        let ethertype = EtherType::from(u16::from_be_bytes([buf[12], buf[13]]));

        let payload = &buf[HEADER_LENGTH..];

        Ok((
            Self {
                dst_mac,
                src_mac,
                ethertype,
            },
            payload,
        ))
    }
}

impl fmt::Display for EthernetHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Destination: ({})", self.dst_mac)?;
        writeln!(f, "Source: ({})", self.src_mac)?;
        writeln!(
            f,
            "Type: {} ({:#06x})",
            self.ethertype,
            self.ethertype.value()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAME_TEST: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // destination (broadcast)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // source
        0x08, 0x00, // EtherType: IPv4
    ];

    #[test]
    fn parses_a_frame() {
        let (h, payload) = EthernetHeader::parse(FRAME_TEST).unwrap();
        assert_eq!(h.dst_mac, MacAddress([0xff; 6]));
        assert_eq!(h.src_mac, MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert_eq!(h.ethertype, EtherType::Ipv4);
        assert!(payload.is_empty());
    }

    #[test]
    fn rejects_buffer_below_minimum() {
        let err = EthernetHeader::parse(&FRAME_TEST[..13]).unwrap_err();
        assert!(matches!(
            err,
            EthernetError::BufferTooShortForHeader {
                expected: 14,
                got: 13
            }
        ));
    }
}
