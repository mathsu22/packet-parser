//! IPv4 (Internet Protocol version 4).
//!
//! ## Module map
//!
//! - [`packet`] — the [`Ipv4Header`] struct and the parsing logic
//! - [`errors`] — [`Ipv4Error`]: every way parsing can fail
//! - [`anomalies`] — [`Ipv4Anomaly`](crate::layer3::ipv4::anomalies::Ipv4Anomaly): non-fatal protocol anomalies detected during parsing
//! - [`protocol`] — [`IpProtocol`](crate::layer3::ipv4::protocol::IpProtocol): the Protocol field as an enum
//! - [`flags`] — [`IpFlags`](crate::layer3::ipv4::flags::IpFlags): the 3-bit Flags field from the IPv4 header, decoded into named booleans
//! - [`display`] — Wireshark-style formatting for [`Ipv4Header`]
//! - [`dscp_ecn`] — helpers for interpreting DSCP and ECN values
//!
//! Checksum computation ([`crate::checksum`]) lives at the crate root,
//! since it's shared with other protocols (ICMP, TCP, UDP).
//!
//! ## References
//!
//! - [RFC 791 – Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)

use crate::layer3::ipv4::{errors::Ipv4Error, packet::Ipv4Header};

pub mod anomalies;
pub mod display;
pub mod dscp_ecn;
pub mod errors;
pub mod flags;
pub mod packet;
pub mod protocol;

/// Parses and prints an IPv4 header.
///
/// Convenience wrapper around [`Ipv4Header::parse`]: everything it
/// returns — decoded header (anomalies included) plus payload — is
/// handed back for further inspection.
///
/// # Errors
///
/// Propagates any [`Ipv4Error`] from [`Ipv4Header::parse`].
pub fn header(buf: &[u8]) -> Result<(Ipv4Header, &[u8]), Ipv4Error> {
    let (data_header, payload) = Ipv4Header::parse(buf)?;

    println!(
        "Internet Protocol Version 4, Src: {}, Dst: {}",
        data_header.source_address, data_header.destination_address
    );
    println!("{}", data_header);

    Ok((data_header, payload))
}
