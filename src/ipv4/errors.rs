//! Every way IPv4 header parsing can fail.

use thiserror::Error;

/// Everything that can go wrong while parsing an IPv4 header.
#[derive(Error, Debug)]
pub enum Ipv4Error {
    /// The buffer is shorter than a valid IPv4 header requires.
    // <https://www.rfc-editor.org/info/rfc6274/#section-3.2>
    #[error("Invalid Buffer Length: Minimum {expected} Bytes, Got {got}")]
    InvalidBufferLength {
        /// The minimum number of bytes a valid header needs.
        expected: usize,
        /// The number of bytes actually present in the buffer.
        got: usize,
    },

    /// The IHL field is below the minimum valid value (5).
    #[error("Invalid IHL: ({0}), minimum (5)")]
    InvalidIhl(u8),

    /// The Version field is invalid; it must be 4.
    #[error("Invalid Version: ({0}), Expected 4")]
    InvalidVersion(u8),
}
