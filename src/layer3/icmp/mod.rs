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

pub mod anomalies;
pub mod display;
pub mod message;
pub mod types;
