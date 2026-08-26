use crate::ipv4::{errors::Ipv4Error, packet::Ipv4Header};

mod dscp_ecn;
pub mod errors;
mod flags;
pub mod packet;
pub mod protocol;

pub fn header(buf: &[u8]) -> Result<Ipv4Header, Ipv4Error> {
    let data_header = Ipv4Header::parse(buf)?;

    println!(
        "Internet Protocol Version 4, Src: {}, Dst: {}",
        data_header.source_address, data_header.destination_address
    );
    println!("{}", data_header);

    Ok(data_header)
}
