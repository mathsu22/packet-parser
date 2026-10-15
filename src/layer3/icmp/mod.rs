//! ICMP (Internet Control Message Protocol).
//!
//! ## Module map
//!
//! - [`message`] — the [`IcmpMessage`] struct and the parsing logic
//! - [`anomalies`] — [`IcmpAnomaly`]: non-fatal protocol anomalies detected during parsing
//! - [`types`] — [`IcmpType`]: the Type byte as an enum
//! - [`display`] — Wireshark-style formatting for [`IcmpMessage`]
//!
//! ## References
//!
//! - [RFC 792 – Internet Control Message Protocol](https://www.rfc-editor.org/rfc/rfc792)

pub mod anomalies;
pub mod display;
pub mod message;
pub mod types;

pub use anomalies::IcmpAnomaly;
pub use message::{IcmpBody, IcmpEcho, IcmpError, IcmpMessage};
pub use types::IcmpType;
