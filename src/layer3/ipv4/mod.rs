//! IPv4: the Network layer (layer 3) of the protocol stack
//! ([RFC 791](https://www.rfc-editor.org/rfc/rfc791)).
//!
//! The entry point is [`header`], which parses a raw byte buffer into an
//! [`Ipv4Header`] and prints a Wireshark-style breakdown of its fields.
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

use crate::layer3::ipv4::{errors::Ipv4Error, packet::Ipv4Header};

pub mod anomalies;
pub mod display;
pub mod dscp_ecn;
pub mod errors;
pub mod flags;
pub mod packet;
pub mod protocol;

/// Parses the IPv4 header from `buf` and prints a Wireshark-style
/// breakdown of it to stdout, returning the parsed [`Ipv4Header`]
/// and the remaining payload.
///
/// Convenience wrapper around [`Ipv4Header::parse`]: parse, print,
/// and hand the header + payload back for further inspection.
///
/// # Errors
///
/// Propagates an [`Ipv4Error`] if `buf` does not contain a valid
/// IPv4 header.
pub fn header(buf: &[u8]) -> Result<(Ipv4Header, &[u8]), Ipv4Error> {
    let (data_header, payload) = Ipv4Header::parse(buf)?;

    println!(
        "Internet Protocol Version 4, Src: {}, Dst: {}",
        data_header.source_address, data_header.destination_address
    );
    println!("{}", data_header);

    Ok((data_header, payload))
}
