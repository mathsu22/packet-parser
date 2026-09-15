//! ICMP (Internet Control Message Protocol).
//!
//! ## Module map
//!
//! - [`message`] — the [`IcmpMessage`] struct and the parsing logic
//! - [`anomalies`] — [`IcmpAnomaly`](crate::layer3::icmp::anomalies::IcmpAnomaly): non-fatal protocol anomalies detected during parsing
//! - [`types`] — [`IcmpType`](crate::layer3::icmp::types::IcmpType): the Type byte as an enum
//! - [`display`] — Wireshark-style formatting for [`IcmpMessage`]
//!
//! ## References
//!
//! - [RFC 792 – Internet Control Message Protocol](https://www.rfc-editor.org/rfc/rfc792)

use crate::layer3::icmp::message::{IcmpError, IcmpMessage};

pub mod anomalies;
pub mod display;
pub mod message;
pub mod types;

/// Dissects and prints an ICMP message.
///
/// Convenience wrapper around [`IcmpMessage::parse`]: everything it
/// returns — decoded message (data and anomalies included) — is
/// handed back for further inspection.
///
/// # Errors
///
/// Propagates any [`IcmpError`] from [`IcmpMessage::parse`].
pub fn dissect(buf: &[u8]) -> Result<(IcmpMessage<'_>, &[u8]), IcmpError> {
    let (message, payload) = IcmpMessage::parse(buf)?;

    println!("Internet Control Message Protocol");

    println!("{}", message);

    Ok((message, payload))
}
