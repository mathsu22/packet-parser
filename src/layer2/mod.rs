//! Data Link layer (Layer 2) protocols.
//!
//! This module contains Data Link layer protocols and their parsers.
//!
//! ## Module map
//!
//! - [`ethernet`] — Ethernet II frame parsing.

pub mod ethernet;

pub use ethernet::{EtherType, EthernetError, EthernetHeader, MacAddress};
