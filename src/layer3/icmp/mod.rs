//! ICMP (Internet Control Message Protocol).
//!
//! ## Module map
//!
//! - [`packet`] — the [`IcmpHeader`] struct and the parsing logic
//! - [`anomalies`] — [`IcmpAnomaly`](crate::layer3::icmp::anomalies::IcmpAnomaly): non-fatal protocol anomalies detected during parsing
//! - [`types`] — [`IcmpType`](crate::layer3::icmp::types::IcmpType): the Type byte as an enum
//! - [`display`] — Wireshark-style formatting for [`IcmpHeader`]
//!
//! ## References
//!
//! - [RFC 792 – Internet Control Message Protocol](https://www.rfc-editor.org/rfc/rfc792)

use crate::layer3::icmp::packet::{IcmpError, IcmpHeader};

pub mod anomalies;
pub mod display;
pub mod packet;
pub mod types;

/// Parses and prints an ICMP message.
///
/// Convenience wrapper around [`IcmpHeader::parse`]: everything it
/// returns — decoded message (data and anomalies included) — is
/// handed back for further inspection.
///
/// # Errors
///
/// Propagates any [`IcmpError`] from [`IcmpHeader::parse`].
pub fn header(buf: &[u8]) -> Result<(IcmpHeader<'_>, &[u8]), IcmpError> {
    let (header, payload) = IcmpHeader::parse(buf)?;

    println!("Internet Control Message Protocol");

    println!("{}", header);

    Ok((header, payload))
}
