//! A packet parser written in Rust for studying network protocols,
//! low-level binary parsing, and the Rust programming language.
//!
//! This is a learning project, built as a foundation for security and
//! ethical hacking: each protocol layer lives in its own module, and
//! the parsing code is heavily commented, so the source doubles as
//! study notes.

#![warn(missing_docs)]

pub mod ipv4;

// ICMP echo request packet (ping):
//    src 192.168.1.104 → dst 8.8.8.8
//    proto = 1 (ICMP), TTL = 64 (Linux)
const PACKET_TEST: &[u8] = &[
    0x45, /* ver/ihl */
    0x00, /* dscp/ecn */
    0x00, 0x54, /* total len */
    0xc6, 0x4a, /* identification */
    0x40, 0x00, /* flags/frag offset */
    0x40, /* ttl */
    0x01, /* protocol */
    0xa2, 0x3e, /* checksum */
    0xc0, 0xa8, 0x01, 0x68, /* source address */
    0x08, 0x08, 0x08, 0x08, /* destination address */
    // ICMP + payload (not broken down yet)
    0x08, 0x00, 0x0e, 0xe4, 0x1e, 0x08, 0x00, 0x01, 0x07, 0xe5, 0x8e, 0x6a, 0x00, 0x00, 0x00, 0x00,
    0x6f, 0xf0, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
];

/// Runs the parser against a hard-coded `ICMPv4` echo-request packet,
/// printing a Wireshark-style breakdown of its IPv4 header.
///
/// # Errors
///
/// Returns an [`ipv4::errors::Ipv4Error`] if the sample packet fails to parse — which,
/// since the packet is hard-coded, would indicate a bug in the parser.
pub fn run() -> Result<(), ipv4::errors::Ipv4Error> {
    print_packet();
    ipv4::header(PACKET_TEST)?;

    Ok(())
}

fn print_packet() {
    println!("Datagram IP: ({}) Bytes:", PACKET_TEST.len());
    for chunks in PACKET_TEST.chunks(8) {
        for b in chunks {
            print!("{:02x} ", b);
        }
        print!("  ");
    }
    println!("\n");
}
