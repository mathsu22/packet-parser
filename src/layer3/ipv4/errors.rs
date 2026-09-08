//! Every way IPv4 header parsing can fail.

use thiserror::Error;

/// Errors that can occur while parsing an IPv4 packet.
///
/// Reference: [RFC 6274 - Security Assessment of IPv4](https://www.rfc-editor.org/info/rfc6274/)
#[derive(Error, Debug)]
pub enum Ipv4Error {
    /// The provided buffer is smaller than the minimum size of an IPv4 header.
    #[error(
        "Buffer too short for a minimal IPv4 header: need at least {expected} bytes, got {got}"
    )]
    BufferTooShortForHeader {
        /// The minimum number of bytes required (always 20).
        expected: usize,
        /// The actual number of bytes present in the buffer.
        got: usize,
    },

    /// The Version field is invalid; it must be 4.
    #[error("Invalid Version: {version}, expected 4 (raw byte 0 = {raw:#04x})")]
    InvalidVersion {
        /// The extracted VERSION value.
        version: u8,
        /// The raw first byte of the header.
        raw: u8,
    },
}
