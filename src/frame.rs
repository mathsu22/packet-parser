//! A dissected packet, represented as a layer tree.
//!
//! [`Frame`] is the root of the tree, containing an Ethernet II header
//! and its payload.
//!
//! Each payload is dispatched to the next layer according to the
//! protocol field of its parent layer.

use crate::{
    errors::AppError,
    layer2::ethernet::{EtherType, EthernetHeader},
    layer3::{
        icmp::message::{IcmpError, IcmpMessage},
        ipv4::{packet::Ipv4Header, protocol::IpProtocol},
    },
};
use std::fmt;

/// The payload of an IPv4 datagram, dispatched by its Protocol field.
pub enum Ipv4Payload<'a> {
    /// An ICMP message, fully decoded.
    Icmp(IcmpMessage<'a>),
    /// The datagram is internally inconsistent, so the payload cannot be
    /// located reliably (invalid IHL or header longer than Total Length).
    Unlocatable,
    /// The datagram is internally consistent, but the capture does not
    /// contain enough bytes to reach or decode the payload.
    NotCaptured,
    /// A protocol (TCP, UDP, ...) not dissected by this parser yet.
    Unsupported(IpProtocol),
}

/// The payload of an Ethernet frame, dispatched by its EtherType field.
pub enum EthernetPayload<'a> {
    /// An IPv4 datagram, containing its header and payload.
    Ipv4 {
        /// The decoded IPv4 header.
        header: Ipv4Header,
        /// The IPv4 datagram's payload.
        payload: Ipv4Payload<'a>,
    },
    /// An EtherType (ARP, IPv6, ...) not dissected by this parser yet.
    Unsupported(EtherType),
}

/// A dissected frame, containing the Ethernet header and its payload.
pub struct Frame<'a> {
    /// The Ethernet II header.
    pub header: EthernetHeader,
    /// The Ethernet payload, dispatched by EtherType.
    pub payload: EthernetPayload<'a>,
}

impl<'a> Frame<'a> {
    /// Parses a frame into a layer tree, starting with the Ethernet header.
    ///
    /// # Errors
    ///
    /// Returns an [`AppError`] from the Ethernet or IPv4 layer.
    pub fn parse(buf: &'a [u8]) -> Result<Self, AppError> {
        let (header, payload) = EthernetHeader::parse(buf)?;
        let ethertype = header.ethertype;
        Ok(Self {
            header,
            payload: EthernetPayload::parse(ethertype, payload)?,
        })
    }
}

impl<'a> EthernetPayload<'a> {
    fn parse(ethertype: EtherType, buf: &'a [u8]) -> Result<Self, AppError> {
        match ethertype {
            EtherType::Ipv4 => {
                let (header, payload) = Ipv4Header::parse(buf)?;
                let ipv4_payload = if !header.locates_payload() {
                    Ipv4Payload::Unlocatable
                } else if !header.header_fits_capture() {
                    Ipv4Payload::NotCaptured
                } else {
                    let protocol = header.protocol;
                    let payload_length = header.payload_length();
                    Ipv4Payload::parse(protocol, payload_length, payload)
                };
                Ok(Self::Ipv4 {
                    header,
                    payload: ipv4_payload,
                })
            }
            other => Ok(Self::Unsupported(other)),
        }
    }
}

impl<'a> Ipv4Payload<'a> {
    fn parse(protocol: IpProtocol, payload_length: usize, buf: &'a [u8]) -> Self {
        match protocol {
            IpProtocol::Icmp => match IcmpMessage::parse(buf, payload_length) {
                Ok(msg) => Self::Icmp(msg),
                Err(IcmpError::BufferTooShortForHeader { .. }) => Self::NotCaptured,
            },
            other => Self::Unsupported(other),
        }
    }
}

impl fmt::Display for Frame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header)?;
        writeln!(f)?;
        write!(f, "{}", self.payload)?;
        Ok(())
    }
}

impl fmt::Display for EthernetPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 { header, payload } => {
                write!(f, "{header}")?;
                writeln!(f)?;
                write!(f, "{payload}")
            }
            Self::Unsupported(ethertype) => writeln!(f, "{ethertype}: not dissected yet"),
        }
    }
}

impl fmt::Display for Ipv4Payload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp(message) => write!(f, "{message}"),
            Self::Unlocatable => writeln!(f, "payload not dissected: unlocatable"),
            Self::NotCaptured => writeln!(f, "payload not captured"),
            Self::Unsupported(protocol) => writeln!(f, "{protocol}: not dissected yet"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PACKET_TEST;
    use crate::checksum::ChecksumStatus;
    use crate::layer3::icmp::message::IcmpBody;
    use crate::layer3::icmp::types::IcmpType;
    use std::net::Ipv4Addr;

    // The happy path, end to end: one frame, three layers, the frame tree
    // carrying each decoded header down to the ICMP type.
    #[test]
    fn frame_tree_carries_the_dissection() {
        let frame = Frame::parse(PACKET_TEST).unwrap();

        let EthernetPayload::Ipv4 { header, payload } = &frame.payload else {
            panic!("expected IPv4");
        };
        let Ipv4Payload::Icmp(message) = payload else {
            panic!("expected ICMP");
        };

        assert_eq!(header.destination_address, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(message.type_, IcmpType::EchoRequest);
    }

    // Ethernet pads small frames: the 6 bytes past the declared message
    // must stay out of `data` and of the checksum window — end-to-end proof
    // of the plumbing (Total Length → payload_length → message_length →
    // available), across all three vocabularies.
    #[test]
    fn padding_beyond_the_datagram_stays_out_of_the_data() {
        let mut padded = PACKET_TEST.to_vec();
        padded.extend_from_slice(&[0xAA; 6]); // fake Ethernet padding
        let frame = Frame::parse(&padded).unwrap();
        let EthernetPayload::Ipv4 { payload, .. } = &frame.payload else {
            panic!("expected IPv4");
        };
        let Ipv4Payload::Icmp(message) = payload else {
            panic!("expected ICMP");
        };
        let IcmpBody::Echo(Some(echo)) = message.body else {
            panic!("expected a complete echo body");
        };
        assert_eq!(echo.data.len(), 56); // 64 − 8, padding excluded
        assert_eq!(message.checksum_status, ChecksumStatus::Good);
    }

    // A lying IHL (4) leaves the payload's location undetermined: the IPv4
    // layer dissects the header and flags the anomaly, but the payload is
    // never offered to the next layer. Crucially, nothing is decoded past
    // the header boundary.
    #[test]
    fn bogus_ihl_leaves_the_payload_unlocatable() {
        let mut pkt = PACKET_TEST.to_vec();
        pkt[14] = 0x44; // IPv4 byte 0: version 4, IHL 4 (Ethernet = 14 bytes)
        let frame = Frame::parse(&pkt).unwrap();
        let EthernetPayload::Ipv4 { header, payload } = &frame.payload else {
            panic!("expected IPv4");
        };
        assert!(matches!(payload, Ipv4Payload::Unlocatable));
        assert_eq!(header.checksum_status, ChecksumStatus::NotVerifiable);
    }

    // The second of the two ways a datagram can be unlocatable: not a lying
    // IHL this time, but a declared Total Length (19) below the declared
    // header (20). The datagram contradicts itself, so the payload is never
    // offered downstream.
    #[test]
    fn datagram_smaller_than_its_header_leaves_the_payload_unlocatable() {
        let mut pkt = PACKET_TEST.to_vec();
        pkt[17] = 0x13; // total_length = 19 (frame offsets 16..=17, big-endian)
        let frame = Frame::parse(&pkt).unwrap();
        let EthernetPayload::Ipv4 { payload, .. } = &frame.payload else {
            panic!("expected IPv4");
        };
        assert!(matches!(payload, Ipv4Payload::Unlocatable));
    }

    // IHL 6 declares a 24-byte header, but only 20 bytes were captured:
    // the datagram is internally consistent, but the capture is truncated.
    // NotCaptured is returned before any payload is offered downstream.
    #[test]
    fn truncated_header_reports_not_captured() {
        let mut pkt = PACKET_TEST.to_vec();
        pkt[14] = 0x46; // version 4, IHL 6 → 24-byte declared header
        let frame = Frame::parse(&pkt[..34]).unwrap(); // Ethernet 14 + 20 of the 24
        let EthernetPayload::Ipv4 { payload, .. } = &frame.payload else {
            panic!("expected IPv4");
        };
        assert!(matches!(payload, Ipv4Payload::NotCaptured));
    }

    // The complete IPv4 header is captured, but the capture holds zero
    // bytes of the declared payload: the next layer cannot read even its
    // first field, so the payload is reported as NotCaptured.
    #[test]
    fn capture_that_reaches_no_payload_bytes_reports_not_captured() {
        let frame = Frame::parse(&PACKET_TEST[..34]).unwrap();
        let EthernetPayload::Ipv4 { payload, .. } = &frame.payload else {
            panic!("expected IPv4");
        };
        assert!(matches!(payload, Ipv4Payload::NotCaptured));
    }

    // IHL 6 redefines the packet: the 4 bytes that headed the ICMP message
    // become IPv4 options (never interpreted, so never validated), the payload
    // shifts down, and the message now declares type 30 (Traceroute per the
    // IANA registry). Nothing contradicts the capture, so the gates pass and
    // the descent happens: the design does not over-cut. The only witness of
    // the mutation is the Bad IPv4 checksum.
    #[test]
    fn valid_ihl_with_options_still_descends() {
        let mut pkt = PACKET_TEST.to_vec();
        pkt[14] = 0x46; // IPv4 byte 0: version 4, IHL 6 → 24-byte header
        let frame = Frame::parse(&pkt).unwrap();

        let EthernetPayload::Ipv4 { header, payload } = &frame.payload else {
            panic!("expected IPv4");
        };
        // The gates pass, the descent is legitimate.
        assert!(header.locates_payload());
        assert!(header.header_fits_capture());
        assert!(header.anomalies.is_empty()); // internally consistent

        let Ipv4Payload::Icmp(message) = payload else {
            panic!("expected the descent to happen");
        };
        let IcmpBody::Other(raw_body) = message.body else {
            panic!("expected the reinterpreted raw body");
        };

        assert!(matches!(message.type_, IcmpType::Unknown(30)));
        assert_eq!(message.code, 8);
        assert_eq!(raw_body.len(), 56); // 60 declared − 4 common header
        assert_eq!(header.checksum_status, ChecksumStatus::Bad); // the only witness
    }
}
