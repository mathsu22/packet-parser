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

pub mod anomalies;
pub mod display;
pub mod dscp_ecn;
pub mod errors;
pub mod flags;
pub mod packet;
pub mod protocol;
