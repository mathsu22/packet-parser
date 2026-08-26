pub mod ipv4;

// ICMP echo request packet (ping):
//    src 192.168.1.104 → dst 8.8.8.8
//    proto = 1 (ICMP), TTL = 64 (Linux)
// Only the 20-byte IPv4 header is included here.
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
];

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
