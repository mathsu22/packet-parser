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
        icmp::message::IcmpMessage,
        ipv4::{packet::Ipv4Header, protocol::IpProtocol},
    },
};
use std::fmt;

/// The payload of an IPv4 datagram, dispatched by its Protocol field.
pub enum Ipv4Payload<'a> {
    /// An ICMP message, fully decoded.
    Icmp(IcmpMessage<'a>),
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
    /// Returns an [`AppError`] from any layer that fails to parse.
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
                let protocol = header.protocol;
                Ok(Self::Ipv4 {
                    header,
                    payload: Ipv4Payload::parse(protocol, payload)?,
                })
            }
            other => Ok(Self::Unsupported(other)),
        }
    }
}

impl<'a> Ipv4Payload<'a> {
    fn parse(protocol: IpProtocol, buf: &'a [u8]) -> Result<Self, AppError> {
        match protocol {
            IpProtocol::Icmp => Ok(Self::Icmp(IcmpMessage::parse(buf)?)),
            other => Ok(Self::Unsupported(other)),
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
            Self::Unsupported(ethertype) => write!(f, "{ethertype}: not dissected yet"),
        }
    }
}

impl fmt::Display for Ipv4Payload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp(message) => write!(f, "{message}"),
            Self::Unsupported(protocol) => write!(f, "{protocol}: not dissected yet"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PACKET_TEST;
    use crate::layer3::icmp::types::IcmpType;
    use std::net::Ipv4Addr;

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
}
