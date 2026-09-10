//! ICMP (Internet Control Message Protocol).
//!
//! ## Module map
//!
//! - [`packet`] — the [`IcmpHeader`](crate::layer3::icmp::packet::IcmpHeader) struct and the parsing logic
//! - [`types`] — [`IcmpType`](crate::layer3::icmp::types::IcmpType): the Type byte as an enum
//!
//! ## References
//!
//! - [RFC 792 – Internet Control Message Protocol](https://www.rfc-editor.org/rfc/rfc792)

pub mod packet;
pub mod types;
