pub mod ipv4;

const PACKET_TEST: &[u8] = &[
    0x45, /* ver/ihl */
    0x00, /* dscp/ecn */
    0x00, 0x54, /* total len */
    0xaf, 0xd3, /* identification */
    0x40, 0x00, /* flags/frag offset */
];

pub fn run() -> Result<(), ipv4::errors::Ipv4Error> {
    print_packet();
    ipv4::header(PACKET_TEST)?;

    Ok(())
}

fn print_packet() {
    println!("Datagram IP: ({}) Bytes:", PACKET_TEST.len());
    for chunks in PACKET_TEST.chunks(4) {
        for b in chunks {
            print!("{:02x} ", b);
        }
        print!("  ");
    }
    println!("\n");
}
