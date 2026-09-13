//! Data Link layer (Layer 2) protocols.
//!
//! This module contains Data Link layer protocols and their parsers.
//!
//! ## Module map
//!
//! - [`ethernet`] — Ethernet II frame parsing.

use crate::layer2::ethernet::{EthernetError, EthernetHeader};

pub mod ethernet;

/// Parses and prints an Ethernet II header.
///
/// Convenience wrapper around [`EthernetHeader::parse`]: everything
/// it returns — decoded header plus payload — is handed back for
/// further inspection.
///
/// # Errors
///
/// Propagates any [`EthernetError`] from [`EthernetHeader::parse`].
pub fn header(buf: &[u8]) -> Result<(EthernetHeader, &[u8]), EthernetError> {
    let (frame_header, payload) = EthernetHeader::parse(buf)?;

    println!(
        "Ethernet II, Src: ({}), Dst: ({})",
        frame_header.src_mac, frame_header.dst_mac
    );

    println!("{}", frame_header);

    Ok((frame_header, payload))
}
