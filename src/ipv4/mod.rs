use crate::ipv4::{errors::Ipv4Error, packet::Ipv4Header};

pub mod dscp_ecn;
pub mod errors;
pub mod packet;

pub fn header(buf: &[u8]) -> Result<Ipv4Header, Ipv4Error> {
    let data_header = Ipv4Header::parse(buf)?;

    println!("Internet Protocol Version 4, ");
    println!("{}", data_header);

    Ok(data_header)
}
