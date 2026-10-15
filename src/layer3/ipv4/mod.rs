//! IPv4 (Internet Protocol version 4).
//!
//! ## Module map
//!
//! - [`packet`] — the [`Ipv4Header`] struct and the parsing logic
//! - [`errors`] — [`Ipv4Error`]: every way parsing can fail
//! - [`anomalies`] — [`Ipv4Anomaly`]: non-fatal protocol anomalies detected during parsing
//! - [`protocol`] — [`IpProtocol`]: the Protocol field as an enum
//! - [`flags`] — [`IpFlags`]: the 3-bit Flags field from the IPv4 header, decoded into named booleans
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

pub use anomalies::{HeaderField, Ipv4Anomaly};
pub use dscp_ecn::{dscp_name, ecn_keyword};
pub use errors::Ipv4Error;
pub use flags::IpFlags;
pub use packet::Ipv4Header;
pub use protocol::IpProtocol;
