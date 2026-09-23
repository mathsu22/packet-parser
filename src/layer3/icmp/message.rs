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
    /// A type not yet mapped by this parser; carries the raw body —
    /// everything past the 4-byte common header.
    Other(&'a [u8]),
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
    /// `message_length` is the length the parent datagram declares for this
    /// message — ICMP has no length field of its own (RFC 792), so the
    /// parent's `payload_length` is the only place it can come from. It
    /// bounds every extended read: the checksum runs over exactly the
    /// declared bytes (Ethernet padding never enters the sum, and a capture
    /// that falls short is [`ChecksumStatus::NotVerifiable`]), body data
    /// ends at the declared edge, and truncation reports the bytes actually
    /// available. `buf` may hold more (padding) or fewer (truncated
    /// capture) bytes than the message was declared to have — every bounded
    /// read takes the lesser of the two.
    ///
    /// Returns the decoded message. Every byte of the message meets one of
    /// three fates: decoded into a field, carried raw ([`IcmpEcho::data`]
    /// for Echo messages, [`IcmpBody::Other`] for unmapped types), or
    /// dropped — when a truncated body cuts a field in half, the half-field
    /// carries no value, only its byte count is recorded as an
    /// [`IcmpAnomaly`]. Nothing is handed further down.
    ///
    /// Dissector semantics: only a buffer too short for the common 4-byte
    /// header fails (see [`IcmpError`]). When the Type demands a body that
    /// the capture or the declared length cannot fill, the message still
    /// dissects and an [`IcmpAnomaly`] is recorded.
    ///
    /// # Errors
    ///
    /// Returns an [`IcmpError`] if the buffer is shorter than the fixed
    /// 4-byte common header.
    pub fn parse(buf: &'a [u8], message_length: usize) -> Result<Self, IcmpError> {
        if buf.len() < MIN_HEADER_LENGTH {
            return Err(IcmpError::BufferTooShortForHeader {
                expected: MIN_HEADER_LENGTH,
                got: buf.len(),
            });
        }

        let type_ = IcmpType::from(buf[0]);
        let code = buf[1];
        let checksum_ = u16::from_be_bytes([buf[2], buf[3]]);

        let available = buf.len().min(message_length);

        let checksum_status = if message_length < MIN_HEADER_LENGTH || buf.len() < message_length {
            ChecksumStatus::NotVerifiable
        } else if checksum(&buf[..message_length]) == 0 {
            ChecksumStatus::Good
        } else {
            ChecksumStatus::Bad
        };

        let mut anomalies = Vec::new();

        let body = match type_ {
            IcmpType::EchoReply | IcmpType::EchoRequest => {
                if available >= ECHO_HEADER_LENGTH {
                    IcmpBody::Echo(Some(IcmpEcho {
                        identifier: u16::from_be_bytes([buf[4], buf[5]]),
                        sequence_number: u16::from_be_bytes([buf[6], buf[7]]),
                        data: &buf[ECHO_HEADER_LENGTH..available],
                    }))
                } else {
                    anomalies.push(IcmpAnomaly::BodyTruncated {
                        expected: ECHO_HEADER_LENGTH,
                        got: available,
                    });
                    IcmpBody::Echo(None)
                }
            }
            IcmpType::Unknown(_) => {
                IcmpBody::Other(&buf[MIN_HEADER_LENGTH..available.max(MIN_HEADER_LENGTH)])
            }
        };

        Ok(Self {
            type_,
            code,
            checksum_,
            checksum_status,
            body,
            anomalies,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PACKET_TEST;

    // The message length the IPv4 datagram declares for the ICMP message
    // inside PACKET_TEST: Total Length (84) − IPv4 header (20).
    const ICMP_MESSAGE_LENGTH: usize = 64;

    // The ICMP message inside PACKET_TEST (Ethernet 14 + IPv4 20).
    fn icmp_test_message() -> &'static [u8] {
        &PACKET_TEST[34..]
    }

    #[test]
    fn parses_the_sample_echo_request() {
        let msg = IcmpMessage::parse(icmp_test_message(), ICMP_MESSAGE_LENGTH).unwrap();
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
        assert!(msg.anomalies.is_empty());
    }

    // The capture contains only 7 of the 8 bytes required by the Echo body:
    // the common header is complete, but Identifier + Sequence Number are truncated.
    #[test]
    fn records_body_truncation_instead_of_failing() {
        let msg = IcmpMessage::parse(&icmp_test_message()[..7], ICMP_MESSAGE_LENGTH).unwrap();
        assert!(matches!(msg.body, IcmpBody::Echo(None)));
        assert!(msg.anomalies.contains(&IcmpAnomaly::BodyTruncated {
            expected: 8,
            got: 7,
        }));
        // Only 7 of the 64 declared bytes were captured, so a partial checksum
        // cannot be verified.
        assert_eq!(msg.checksum_status, ChecksumStatus::NotVerifiable);
    }

    // Boundary: exactly 8 bytes is a valid RFC 792 Echo message — a complete
    // body with no data. It is NOT truncated. Checksum verification still fails:
    // body completeness and checksum verifiability are independent.
    #[test]
    fn echo_with_no_data_is_a_complete_body() {
        let msg = IcmpMessage::parse(&icmp_test_message()[..8], ICMP_MESSAGE_LENGTH).unwrap();
        let IcmpBody::Echo(Some(echo)) = msg.body else {
            panic!("expected a complete echo body");
        };
        assert!(echo.data.is_empty());
        assert!(msg.anomalies.is_empty());
        assert_eq!(msg.checksum_status, ChecksumStatus::NotVerifiable);
    }

    // Boundary: exactly 4 bytes is enough for the common ICMP header,
    // but not enough for the Echo body.
    #[test]
    fn four_bytes_dissect_with_truncated_body() {
        let msg = IcmpMessage::parse(&icmp_test_message()[..4], ICMP_MESSAGE_LENGTH).unwrap();
        assert!(matches!(msg.body, IcmpBody::Echo(None)));
        assert!(msg.anomalies.contains(&IcmpAnomaly::BodyTruncated {
            expected: 8,
            got: 4,
        }));
    }

    #[test]
    fn rejects_buffer_below_minimum() {
        let err = IcmpMessage::parse(&icmp_test_message()[..3], ICMP_MESSAGE_LENGTH).unwrap_err();
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
        let msg = IcmpMessage::parse(&raw_msg, ICMP_MESSAGE_LENGTH).unwrap();
        assert!(matches!(msg.type_, IcmpType::Unknown(47)));
        // Unknown types are preserved without interpretation: the bytes after
        // the common 4-byte header are returned unchanged as the raw body.
        let IcmpBody::Other(raw_body) = msg.body else {
            panic!("expected the raw body");
        };
        assert_eq!(raw_body.len(), raw_msg.len() - 4);
        assert_eq!(raw_body, &raw_msg[4..]);
    }

    // Ethernet padding extends the capture beyond the declared datagram:
    // those 6 bytes must be excluded from both `data` and the checksum window.
    #[test]
    fn padding_beyond_the_datagram_stays_out_of_the_data() {
        let mut padded = icmp_test_message().to_vec();
        padded.extend_from_slice(&[0xAA; 6]); // fake Ethernet padding
        let msg = IcmpMessage::parse(&padded, ICMP_MESSAGE_LENGTH).unwrap();
        let IcmpBody::Echo(Some(echo)) = msg.body else {
            panic!("expected a complete echo body");
        };
        assert_eq!(echo.data.len(), 56); // 64 − 8, padding excluded
        assert_eq!(msg.checksum_status, ChecksumStatus::Good);
    }

    // The parent datagram declares fewer bytes than the 4-byte ICMP common header:
    // the body is truncated, parsing does not panic, and the checksum is not verifiable.
    #[test]
    fn parent_declaring_less_than_the_common_header_does_not_panic() {
        let msg = IcmpMessage::parse(icmp_test_message(), 2).unwrap();
        assert!(matches!(msg.body, IcmpBody::Echo(None)));
        assert!(msg.anomalies.contains(&IcmpAnomaly::BodyTruncated {
            expected: 8,
            got: 2,
        }));
        assert_eq!(msg.checksum_status, ChecksumStatus::NotVerifiable);
    }

    // The `Other` arm slices `&buf[4..available]`. With a declared length
    // below the 4-byte common header, `available` would be smaller than 4,
    // making the range invalid. The `max(4)` guard keeps the range empty
    // instead of attempting a backwards slice.
    #[test]
    fn unmapped_type_with_tiny_declaration_does_not_panic() {
        let mut raw = icmp_test_message().to_vec();
        raw[0] = 47; // unmapped, reaches the Other arm
        let msg = IcmpMessage::parse(&raw, 2).unwrap();

        let IcmpBody::Other(raw_body) = msg.body else {
            panic!("expected the raw body");
        };
        assert!(raw_body.is_empty()); // the guard: nothing to locate
        assert_eq!(msg.checksum_status, ChecksumStatus::NotVerifiable);
    }
}
