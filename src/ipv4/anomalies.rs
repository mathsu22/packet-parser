//! IPv4 header parsing anomalies.

use std::fmt;

/// Anomalies detected during IPv4 header parsing.
///
/// Unlike [`Ipv4Error`](crate::ipv4::errors::Ipv4Error), these do not halt parsing.
/// They are collected and displayed as "Expert Info" warnings, mimicking Wireshark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv4Anomaly {
    /// The capture buffer is shorter than the header length declared by IHL.
    HeaderLongerThanCapture {
        /// The number of bytes actually captured.
        captured: usize,
        /// The declared header length in bytes (IHL × 4).
        declared: usize,
    },
    /// The declared header length is greater than the Total Length.
    HeaderExceedsTotalLength {
        /// Header length in bytes.
        header_length: usize,
        /// Total length in bytes
        total_length: usize,
    },
    /// The Total Length field exceeds the actual captured buffer size.
    TotalLengthExceedsCapture {
        /// The actual captured buffer size in bytes.
        captured: usize,
    },
    /// The Reserved flag bit is set (must be zero).
    ReservedFlagSet,
    /// The IHL declares a size smaller than the minimum 20 bytes.
    InvalidIhl(u8),
}

/// The header field to which an [`Ipv4Anomaly`] refers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderField {
    /// Refers to the Header Length (IHL) field.
    HeaderLength,
    /// Refers to the Total Length field.
    TotalLength,
    /// Refers to the Flags field.
    Flags,
}

impl Ipv4Anomaly {
    /// Returns the header field this anomaly refers to.
    pub fn field(&self) -> HeaderField {
        match self {
            Self::InvalidIhl(_) | Self::HeaderLongerThanCapture { .. } => HeaderField::HeaderLength,
            Self::HeaderExceedsTotalLength { .. } | Self::TotalLengthExceedsCapture { .. } => {
                HeaderField::TotalLength
            }
            Self::ReservedFlagSet => HeaderField::Flags,
        }
    }
}

impl fmt::Display for Ipv4Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderLongerThanCapture { captured, .. } => {
                write!(
                    f,
                    "IPv4 Header Length exceeds capture length ({captured} bytes)"
                )
            }
            Self::HeaderExceedsTotalLength {
                header_length,
                total_length,
            } => write!(
                f,
                "IPv4 header length ({header_length}) exceeds Total Length ({total_length})"
            ),
            Self::TotalLengthExceedsCapture { captured } => {
                write!(
                    f,
                    "IPv4 Total Length exceeds capture length ({captured} bytes)"
                )
            }
            Self::ReservedFlagSet => write!(f, "Reserved bit is set (must be zero)"),
            Self::InvalidIhl(ihl) => write!(f, "Invalid IHL: {ihl}, minimum 5"),
        }
    }
}
