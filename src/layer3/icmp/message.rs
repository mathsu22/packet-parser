//! ICMP (Internet Control Message Protocol) dissector
//!
//! Unlike IPv4, ICMP has no length field of its own and no fixed body
//! shape: only the first 4 bytes (Type, Code, Checksum) mean the same
//! thing for every message. What comes after depends entirely on the Type.

use crate::{
    checksum::{ChecksumStatus, checksum},
    layer3::icmp::{anomalies::IcmpAnomaly, types::IcmpType},
};
use thiserror::Error;

/// Every ICMP message has at least Type (1) + Code (1) + Checksum (2).
const MIN_HEADER_LENGTH: usize = 4;

/// Echo Request/Reply add Identifier (2) + Sequence Number (2) on top
/// of the common 4-byte header.
const ECHO_HEADER_LENGTH: usize = 8;

/// The body of an Echo Request/Reply message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpEcho<'a> {
    /// Identifies which `ping` session this message belongs to.
    pub identifier: u16,
    /// Incremented on each Echo Request sent, so replies can be matched
    /// to requests and reordering/loss can be detected.
    pub sequence_number: u16,
    /// The data carried by the message: everything past the 8-byte echo
    /// header, kept raw — no protocol sits below ICMP to dissect it
    /// further. Covered by the checksum, which in ICMP sums the entire
    /// message.
    pub data: &'a [u8],
}

/// The type-specific body of an ICMP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpBody<'a> {
    /// Echo Request or Echo Reply body.
    Echo(Option<IcmpEcho<'a>>),
    /// A type not yet mapped by this parser.
    Other,
}

/// Every way ICMP message parsing can fail.
#[derive(Error, Debug)]
pub enum IcmpError {
    /// The buffer is smaller than the minimum common header (4 bytes).
    #[error("Buffer too short for an ICMP header: need at least {expected} bytes, got {got}")]
    BufferTooShortForHeader {
        /// Always 4.
        expected: usize,
        /// The actual number of bytes present.
        got: usize,
    },
}

/// The decoded fields of an ICMP message.
#[derive(Debug)]
pub struct IcmpMessage<'a> {
    /// What kind of ICMP message this is.
    pub type_: IcmpType,
    /// Sub-classifies the Type.
    pub code: u8,
    /// Checksum covering the entire ICMP message (header + data).
    pub checksum_: u16,
    /// Whether the checksum verified during `parse`.
    pub checksum_status: ChecksumStatus,
    /// The type-specific body.
    pub body: IcmpBody<'a>,
    /// Protocol-level anomalies detected during parsing.
    pub anomalies: Vec<IcmpAnomaly>,
}

impl<'a> IcmpMessage<'a> {
    /// Parses an ICMP message from `buf`.
    ///
    /// Returns the decoded message and the undecoded remainder — empty
    /// for Echo messages, whose data is part of the decoded body; the raw
    /// body for types this parser doesn't map yet.
    ///
    /// Dissector semantics: only a buffer too short for the common 4-byte
    /// header fails (see [`IcmpError`]). When the Type demands a body that
    /// doesn't fit in the capture, the message still dissects and an
    /// [`IcmpAnomaly`] is recorded.
    ///
    /// # Errors
    ///
    /// Returns an [`IcmpError`] if the buffer is shorter than the fixed
    /// 4-byte common header.
    pub fn parse(buf: &'a [u8]) -> Result<(Self, &'a [u8]), IcmpError> {
        if buf.len() < MIN_HEADER_LENGTH {
            return Err(IcmpError::BufferTooShortForHeader {
                expected: MIN_HEADER_LENGTH,
                got: buf.len(),
            });
        }

        let type_ = IcmpType::from(buf[0]);
        let code = buf[1];
        let checksum_ = u16::from_be_bytes([buf[2], buf[3]]);

        let checksum_status = if checksum(buf) == 0 {
            ChecksumStatus::Good
        } else {
            ChecksumStatus::Bad
        };

        let mut anomalies = Vec::new();

        let (body, payload) = match type_ {
            IcmpType::EchoReply | IcmpType::EchoRequest => {
                if buf.len() >= ECHO_HEADER_LENGTH {
                    (
                        IcmpBody::Echo(Some(IcmpEcho {
                            identifier: u16::from_be_bytes([buf[4], buf[5]]),
                            sequence_number: u16::from_be_bytes([buf[6], buf[7]]),
                            data: &buf[ECHO_HEADER_LENGTH..],
                        })),
                        &buf[buf.len()..],
                    )
                } else {
                    anomalies.push(IcmpAnomaly::BodyTruncated {
                        expected: ECHO_HEADER_LENGTH,
                        got: buf.len(),
                    });
                    (IcmpBody::Echo(None), &buf[buf.len()..])
                }
            }
            _ => (IcmpBody::Other, &buf[MIN_HEADER_LENGTH..]),
        };

        Ok((
            Self {
                type_,
                code,
                checksum_,
                checksum_status,
                body,
                anomalies,
            },
            payload,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PACKET_TEST;

    /// The ICMP message inside PACKET_TEST (Ethernet 14 + IPv4 20).
    fn icmp_test_message() -> &'static [u8] {
        &PACKET_TEST[34..]
    }

    #[test]
    fn parses_the_sample_echo_request() {
        let (msg, payload) = IcmpMessage::parse(icmp_test_message()).unwrap();
        assert_eq!(msg.type_, IcmpType::EchoRequest);
        assert_eq!(msg.code, 0);
        assert_eq!(msg.checksum_, 0x0ee4);
        assert_eq!(msg.checksum_status, ChecksumStatus::Good);
        let IcmpBody::Echo(Some(echo)) = msg.body else {
            panic!("expected a complete echo body");
        };
        assert_eq!(echo.identifier, 0x1e08);
        assert_eq!(echo.sequence_number, 1);
        assert_eq!(echo.data.len(), 56);
        assert_eq!(&echo.data[..4], &[0x07, 0xe5, 0x8e, 0x6a]);
        assert!(payload.is_empty()); // the data lives inside the body
        assert!(msg.anomalies.is_empty());
    }

    // A capture truncated to 7 of the 8 bytes the echo body needs:
    // the common header reads fine, but Identifier + Sequence don't fit.
    #[test]
    fn records_body_truncation_instead_of_failing() {
        let (msg, payload) = IcmpMessage::parse(&icmp_test_message()[..7]).unwrap();
        assert!(matches!(msg.body, IcmpBody::Echo(None)));
        assert!(msg.anomalies.contains(&IcmpAnomaly::BodyTruncated {
            expected: 8,
            got: 7,
        }));
        assert_eq!(msg.checksum_status, ChecksumStatus::Bad); // data is missing
        assert!(payload.is_empty());
    }

    // Boundary: exactly 8 bytes is a legal RFC 792 message — complete
    // body, empty data. NOT truncated.
    #[test]
    fn echo_with_no_data_is_a_complete_body() {
        let (msg, payload) = IcmpMessage::parse(&icmp_test_message()[..8]).unwrap();
        let IcmpBody::Echo(Some(echo)) = msg.body else {
            panic!("expected a complete echo body");
        };
        assert!(echo.data.is_empty());
        assert!(payload.is_empty());
        assert!(msg.anomalies.is_empty());
    }

    // Just above the fatal floor: common header present, body absent.
    #[test]
    fn four_bytes_dissect_with_truncated_body() {
        let (msg, _) = IcmpMessage::parse(&icmp_test_message()[..4]).unwrap();
        assert!(matches!(msg.body, IcmpBody::Echo(None)));
        assert!(msg.anomalies.contains(&IcmpAnomaly::BodyTruncated {
            expected: 8,
            got: 4,
        }));
    }

    #[test]
    fn rejects_buffer_below_minimum() {
        let err = IcmpMessage::parse(&icmp_test_message()[..3]).unwrap_err();
        assert!(matches!(
            err,
            IcmpError::BufferTooShortForHeader {
                expected: 4,
                got: 3
            }
        ));
    }

    #[test]
    fn unknown_type_yields_the_undecoded_remainder() {
        let mut raw_msg = icmp_test_message().to_vec();
        raw_msg[0] = 47; // not mapped
        let (msg, payload) = IcmpMessage::parse(&raw_msg).unwrap();
        assert!(matches!(msg.type_, IcmpType::Unknown(47)));
        assert!(matches!(msg.body, IcmpBody::Other));
        assert_eq!(payload.len(), raw_msg.len() - 4); // the residual contract
    }
}
