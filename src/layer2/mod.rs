//! Data Link layer (Layer 2) protocols.
//!
//! This module contains Data Link layer protocols and their parsers.
//!
//! ## Module map
//!
//! - [`ethernet`] — Ethernet II frame parsing.

use crate::layer2::ethernet::{EthernetError, EthernetHeader};

pub mod ethernet;

/// Parses the Ethernet II header from `buf` and prints a Wireshark-style
/// breakdown of it to stdout, returning the parsed [`EthernetHeader`]
/// and the remaining payload.
///
/// Convenience wrapper around [`EthernetHeader::parse`]: parse, print,
/// and hand the header + payload back for further inspection.
///
/// # Errors
///
/// Propagates an [`EthernetError`] if `buf` does not contain a valid
/// Ethernet II header.
pub fn header(buf: &[u8]) -> Result<(EthernetHeader, &[u8]), EthernetError> {
    let (frame_header, payload) = EthernetHeader::parse(buf)?;

    println!(
        "Ethernet II, Src: ({}), Dst: ({})",
        frame_header.src_mac, frame_header.dst_mac
    );

    println!("{}", frame_header);

    Ok((frame_header, payload))
}
