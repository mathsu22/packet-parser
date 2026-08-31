//! Layer 3: the IPv4 packet header.
//!
//! Ethernet was a fixed 14 bytes. IPv4 is *variable length*: the header is
//! normally 20 bytes but can carry up to 40 bytes of options. You don't know
//! where the payload begins until you read the **IHL** field. Get that wrong
//! and every layer above it decodes garbage — or you read out of bounds. So
//! this is where careful, length-driven parsing really starts to matter.

use crate::ipv4::{
    anomalies::Ipv4Anomaly,
    checksum::{ChecksumStatus, checksum},
    errors::Ipv4Error,
    flags::IpFlags,
    protocol::IpProtocol,
};
use std::net::Ipv4Addr;

// IPv4 IHL is expressed in 32-bit words.
// 5 words × 4 bytes = 20 bytes minimum.
const MIN_HEADER_LENGTH: usize = 20;

const MIN_IHL_VALUE: u8 = 5;
const IPV4_VERSION: u8 = 4;

/// Represents the decoded fields of an IPv4 packet header.
#[derive(Debug)]
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
    pub header_checksum: u16,
    /// Source IPv4 address.
    pub source_address: Ipv4Addr,
    /// Destination IPv4 address.
    pub destination_address: Ipv4Addr,
    /// Whether the header checksum verified during `parse`.
    pub checksum_status: ChecksumStatus,
    /// Protocol-level anomalies detected during parsing.
    pub anomalies: Vec<Ipv4Anomaly>,
}

impl Ipv4Header {
    /// Parses an IPv4 header from its raw bytes.
    pub fn parse(buf: &[u8]) -> Result<Self, Ipv4Error> {
        let buf_length = buf.len();
        if buf_length < MIN_HEADER_LENGTH {
            return Err(Ipv4Error::BufferTooShortForHeader {
                expected: MIN_HEADER_LENGTH,
                got: buf_length,
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
            return Err(Ipv4Error::InvalidVersion { version, raw: b0 });
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

        let mut anomalies = Vec::new();
        let ihl = b0 & 0x0F;

        // The IHL field does NOT store the header size in bytes.
        // Instead, it stores the number of **32-bit words (4 bytes)** in the header.
        // In computer architecture, a "word" is a fixed-size unit of data.
        // 1 byte = 8 bits
        // 32 bits = 4 bytes
        // Therefore, 1 word (in this context) = 4 bytes.
        // The IHL field is only 4 bits wide, meaning it can only represent values from 0 to 15.
        // However, the minimum IPv4 header size is 20 bytes.
        // To accommodate this, IHL stores the count of 4-byte blocks.
        // Minimum IPv4 header: 20 bytes / 4 = 5 (minimum valid IHL).
        // Maximum IPv4 header: 15 (max IHL value) * 4 bytes = 60 bytes.
        let mut header_length = (ihl as usize) * 4;
        if ihl < MIN_IHL_VALUE {
            anomalies.push(Ipv4Anomaly::InvalidIhl(ihl));
            header_length = MIN_HEADER_LENGTH;
        }
        let declared_header_length = header_length;

        // Ex.: buffer cannot be 20 bytes and header_length be 24
        if buf_length < header_length {
            anomalies.push(Ipv4Anomaly::HeaderLongerThanCapture {
                captured: buf_length,
                declared: declared_header_length,
            });
            // Locks the header size to the buffer size to avoid reading garbage data
            header_length = buf_length;
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
        //  Multi-byte IPv4 fields use network byte order (big-endian).
        //  from_be_bytes builds a u16 treating the first byte as the high byte.
        let total_length = u16::from_be_bytes([buf[2], buf[3]]);

        // For obvious reasons, the Internet header cannot be larger than the
        // whole Internet datagram of which it is part.  Therefore, the
        // following check should be enforced:
        if declared_header_length > total_length as usize {
            anomalies.push(Ipv4Anomaly::HeaderExceedsTotalLength {
                header_length: declared_header_length,
                total_length: total_length as usize,
            });
        }

        if buf_length < total_length as usize {
            anomalies.push(Ipv4Anomaly::TotalLengthExceedsCapture {
                captured: buf_length,
            });
        }
        // Bytes 4..=5 — identification (16 bits, big-endian)
        let identification = u16::from_be_bytes([buf[4], buf[5]]);

        //  Bytes 6..=7 — flags (3 bits) + fragment_offset (13 bits)
        let word = u16::from_be_bytes([buf[6], buf[7]]);

        // shift >> 13 to isolate the flags (3 bits)
        let raw_flags = (word >> 13) as u8;
        let flags = IpFlags::parse(raw_flags);
        if flags.is_anomalous() {
            anomalies.push(Ipv4Anomaly::ReservedFlagSet);
        }

        // & 0x1FFF to isolate the fragment offset (13 bits)
        let fragment_offset = word & 0x1FFF;

        //  BYTES 8..=11 — TTL, protocol, header checksum
        let ttl = buf[8];
        let protocol = IpProtocol::from(buf[9]);
        let header_checksum = u16::from_be_bytes([buf[10], buf[11]]);

        //  BYTES 12..=15 — source IP
        let source_address = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        //  BYTES 16..=19 — destination IP
        let destination_address = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

        let checksum_status = if buf_length < declared_header_length {
            ChecksumStatus::NotVerifiable
        } else if checksum(&buf[..header_length]) == 0 {
            ChecksumStatus::Good
        } else {
            ChecksumStatus::Bad
        };

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
            header_checksum,
            source_address,
            destination_address,
            checksum_status,
            anomalies,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PACKET_TEST;

    // happy path

    // Ground truth: this packet was captured for real and checked
    #[test]
    fn parses_the_sample_packet() {
        let h = Ipv4Header::parse(PACKET_TEST).unwrap();
        assert_eq!(h.version, 4);
        assert_eq!(h.ihl, 5);
        assert_eq!(h.total_length, 84);
        assert_eq!(h.identification, 0xc64a);
        assert_eq!(
            h.flags,
            IpFlags {
                reserved: false,
                dont_fragment: true,
                more_fragments: false
            }
        );
        assert_eq!(h.fragment_offset, 0);
        assert_eq!(h.ttl, 64);
        assert_eq!(h.protocol, IpProtocol::Icmp);
        assert_eq!(h.header_checksum, 0xa23e);
        assert_eq!(h.source_address, Ipv4Addr::new(192, 168, 1, 104));
        assert_eq!(h.destination_address, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(h.checksum_status, ChecksumStatus::Good);
        assert!(h.anomalies.is_empty());
    }

    #[test]
    fn rejects_buffer_one_byte_below_minimum() {
        let err = Ipv4Header::parse(&PACKET_TEST[..19]).unwrap_err();
        assert!(matches!(
            err,
            Ipv4Error::BufferTooShortForHeader {
                expected: 20,
                got: 19
            }
        ));
    }

    #[test]
    fn rejects_ipv6_fed_to_ipv4_parser() {
        let mut pkt = PACKET_TEST.to_vec();
        pkt[0] = 0x60;
        assert!(matches!(
            Ipv4Header::parse(&pkt).unwrap_err(),
            Ipv4Error::InvalidVersion {
                version: 6,
                raw: 0x60
            }
        ));
    }

    #[test]
    fn anomaly_invalid_ihl_below_minimum() {
        // IHL 4 (16-byte header) is below the RFC minimum of 5 (20 bytes).
        // The parser doesn't abort: it clamps to the minimum and flags the anomaly.
        let mut pkt = PACKET_TEST.to_vec();
        pkt[0] = 0x44; // version 4, IHL 4
        let h = Ipv4Header::parse(&pkt).unwrap();
        assert!(h.anomalies.contains(&Ipv4Anomaly::InvalidIhl(4)));
    }

    #[test]
    fn anomaly_header_longer_than_capture() {
        // IHL 6 declares a 24-byte header, but only 20 bytes were captured.
        // Both the header-vs-capture and total-length-vs-capture checks fire,
        // and the checksum can't be verified since the declared header is
        // longer than what's actually available.
        let mut pkt = PACKET_TEST.to_vec();
        pkt[0] = 0x46; // version 4, IHL 6
        let h = Ipv4Header::parse(&pkt[..20]).unwrap();
        assert!(h.anomalies.contains(&Ipv4Anomaly::HeaderLongerThanCapture {
            captured: 20,
            declared: 24,
        }));
        assert!(
            h.anomalies
                .contains(&Ipv4Anomaly::TotalLengthExceedsCapture { captured: 20 })
        );
        assert_eq!(h.checksum_status, ChecksumStatus::NotVerifiable);
    }

    #[test]
    fn anomaly_header_exceeding_total_length() {
        // total_length = 19 is smaller than the 20-byte header itself —
        // logically impossible for a real datagram.
        let mut pkt = PACKET_TEST.to_vec();
        pkt[3] = 0x13; // total_length = 19
        let h = Ipv4Header::parse(&pkt).unwrap();
        assert_eq!(h.total_length, 19);
        assert!(
            h.anomalies
                .contains(&Ipv4Anomaly::HeaderExceedsTotalLength {
                    header_length: 20,
                    total_length: 19,
                })
        );
    }

    #[test]
    fn anomaly_total_length_exceeding_capture() {
        // The header declares 84 bytes, but only 83 were captured — a
        // truncated capture. The header itself is intact, so the checksum
        // still verifies fine; only the payload is short.
        let h = Ipv4Header::parse(&PACKET_TEST[..83]).unwrap();
        assert!(
            h.anomalies
                .contains(&Ipv4Anomaly::TotalLengthExceedsCapture { captured: 83 })
        );
        assert_eq!(h.checksum_status, ChecksumStatus::Good);
    }

    #[test]
    fn anomaly_reserved_bit_set() {
        // word = 0xA000 → flags = 0b101 (Reserved + More Fragments).
        let mut pkt = PACKET_TEST.to_vec();
        pkt[6] = 0xA0;
        let h = Ipv4Header::parse(&pkt).unwrap();
        assert!(h.flags.reserved);
        assert_eq!(h.anomalies, vec![Ipv4Anomaly::ReservedFlagSet]);
    }

    #[test]
    fn records_bad_checksum_instead_of_failing() {
        // Flipping the TTL byte corrupts the checksum, but doesn't touch
        // any of the length/version/IHL fields — parsing still succeeds,
        // and the corrupted field is still readable.
        let mut pkt = PACKET_TEST.to_vec();
        pkt[8] ^= 0xFF; // TTL: 0x40 → 0xBF
        let h = Ipv4Header::parse(&pkt).unwrap();
        assert_eq!(h.checksum_status, ChecksumStatus::Bad);
        assert_eq!(h.ttl, 0xBF);
        assert!(h.anomalies.is_empty());
    }

    #[test]
    fn reports_every_lie_a_packet_tells() {
        // buf=20, IHL=6 (declares 24), total=22: the packet contradicts
        // itself three ways, and all three findings must be recorded —
        // the clamped read length must NOT suppress any of them.
        let mut pkt = PACKET_TEST.to_vec();
        pkt[0] = 0x46;
        pkt[3] = 0x16; // total_length = 22
        let h = Ipv4Header::parse(&pkt[..20]).unwrap();
        assert!(h.anomalies.contains(&Ipv4Anomaly::HeaderLongerThanCapture {
            captured: 20,
            declared: 24,
        }));
        assert!(
            h.anomalies
                .contains(&Ipv4Anomaly::HeaderExceedsTotalLength {
                    header_length: 24, // the DECLARED length, not the clamped 20
                    total_length: 22,
                })
        );
        assert!(
            h.anomalies
                .contains(&Ipv4Anomaly::TotalLengthExceedsCapture { captured: 20 })
        );
    }

    #[test]
    fn accepts_padding_beyond_total_length() {
        // Ethernet pads small frames, so a capture can legitimately be
        // LONGER than the datagram: excess bytes are not an anomaly.
        let mut padded = PACKET_TEST.to_vec();
        padded.extend_from_slice(&[0x00; 6]); // fake Ethernet padding
        let h = Ipv4Header::parse(&padded).unwrap();
        assert!(h.anomalies.is_empty());
        assert_eq!(h.checksum_status, ChecksumStatus::Good);
    }
}
