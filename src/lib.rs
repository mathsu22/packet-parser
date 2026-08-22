pub mod ipv4;

const PACKET_TEST: &[u8] = &[0x45, 0x00, 0x00, 0x54, 0xaf, 0xd3];

pub fn run() -> Result<(), ipv4::errors::Ipv4Error> {
    print_packet();
    ipv4::header(PACKET_TEST)?;

    Ok(())
}

fn print_packet() {
    println!("Datagram IP: ({}) Bytes:", PACKET_TEST.len());
    for chunks in PACKET_TEST.chunks(3) {
        for b in chunks {
            print!("{:02x} ", b);
        }
        print!("  ");
    }
    println!("\n");
}
