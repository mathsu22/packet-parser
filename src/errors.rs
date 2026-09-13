//! The top-level error type this crate returns from [`crate::run`],
//! aggregating every layer's error into one enum.

use thiserror::Error;

use crate::{
    layer2::ethernet::EthernetError,
    layer3::{icmp::packet::IcmpError, ipv4::errors::Ipv4Error},
};

/// Errors that can occur while running the packet parser end-to-end,
/// covering every layer it currently understands.
#[derive(Error, Debug)]
pub enum AppError {
    /// Failed while parsing the Ethernet (Layer 2).
    #[error("Ethernet Error: {0}")]
    Ethernet(#[from] EthernetError),

    /// Failed while parsing the IPv4 (Layer 3).
    #[error("IPv4 Error: {0}")]
    Ipv4(#[from] Ipv4Error),

    /// Failed while parsing the ICMP (Layer 3).
    #[error("ICMP Error: {0}")]
    Icmp(#[from] IcmpError),
}
