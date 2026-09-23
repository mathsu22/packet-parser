//! The top-level error type returned by [`crate::frame::Frame::parse`].

use thiserror::Error;

use crate::{layer2::ethernet::EthernetError, layer3::ipv4::errors::Ipv4Error};

/// Errors that can halt the dissection fatally. Only Ethernet and
/// IPv4 can do that: nothing below IPv4 kills the frame — every
/// failure there becomes a branch of the tree.
#[derive(Error, Debug)]
pub enum AppError {
    /// Failed while parsing the Ethernet (Layer 2).
    #[error("Ethernet Error: {0}")]
    Ethernet(#[from] EthernetError),

    /// Failed while parsing the IPv4 (Layer 3).
    #[error("IPv4 Error: {0}")]
    Ipv4(#[from] Ipv4Error),
}
