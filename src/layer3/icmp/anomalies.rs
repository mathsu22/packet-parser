//! ICMP message parsing anomalies.

use std::fmt;

/// Anomalies detected during ICMP message parsing.
///
/// Unlike [`IcmpError`](crate::layer3::icmp::message::IcmpError), these do not halt parsing.
/// They are collected and displayed as "Expert Info" warnings, mimicking Wireshark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpAnomaly {
    /// The Type dispatches a body of `expected` bytes, but fewer
    /// were captured — body fields are unavailable.
    BodyTruncated {
        /// Minimum message size the Type demands (common header + body).
        expected: usize,
        /// Bytes of the message actually captured.
        got: usize,
    },
}

impl fmt::Display for IcmpAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BodyTruncated { expected, got } => {
                write!(
                    f,
                    "Malformed Packet (Exception occurred): {expected} bytes needed, {got} captured"
                )
            }
        }
    }
}
