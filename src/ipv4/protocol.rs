use std::fmt;

// TODO: implement the remaining protocols
// https://www.iana.org/assignments/protocol-numbers
/// The 8-bit "Protocol" field: what the IPv4 payload is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Tcp,
    Udp,
    Unknown(u8),
}

// Convert u8 to protocol enum
impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            x => Self::Unknown(x),
        }
    }
}

// Convert protocol enum to u8
impl IpProtocol {
    pub fn value(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Unknown(x) => x,
        }
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp => write!(f, "ICMP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Unknown(_) => write!(f, "Unknown"),
        }
    }
}
