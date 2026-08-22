use thiserror::Error;

#[derive(Error, Debug)]
pub enum Ipv4Error {
    // https://www.rfc-editor.org/info/rfc6274/#section-3.2
    #[error("Invalid Buffer Length: Minimum {expected} Bytes, Got {got}")]
    InvalidBufferLength { expected: usize, got: usize },

    #[error("Invalid IHL: ({0}), minimum (5)")]
    InvalidIhl(u8),

    #[error("Invalid Version: ({0}), Expected 4")]
    InvalidVersion(u8),
}
