//! Flags: 3 bits (after the shift >> 13 in packet.rs)
//!
//! Bit 2: Reserved (must be zero)
//! Bit 1: DF — 0 = May Fragment, 1 = Don't Fragment
//! Bit 0: MF — 0 = Last Fragment, 1 = More Fragments

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpFlags {
    pub reserved: bool,
    pub dont_fragment: bool,
    pub more_fragments: bool,
}

impl IpFlags {
    /// Parses the 3-bit flags field into individual boolean flags.
    pub fn parse(flags_value: u8) -> Self {
        Self {
            reserved: flags_value & 0b100 != 0,
            dont_fragment: flags_value & 0b010 != 0,
            more_fragments: flags_value & 0b001 != 0,
        }
    }

    /// Reconstructs the packed 3-bit representation (reserved | DF | MF),
    /// for hex/debug display
    pub fn as_byte(&self) -> u8 {
        (self.reserved as u8) << 2 | (self.dont_fragment as u8) << 1 | (self.more_fragments as u8)
    }

    /// A set reserved bit doesn't make the packet invalid; it's just an anomaly
    /// worth flagging (Wireshark treats it the same way: a Warning, not an error).
    pub fn is_anomalous(&self) -> bool {
        self.reserved
    }
}

impl fmt::Display for IpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut set = Vec::new();
        if self.reserved {
            set.push("Reserved");
        }
        if self.dont_fragment {
            set.push("Don't Fragment");
        }
        if self.more_fragments {
            set.push("More Fragments");
        }
        if set.is_empty() {
            write!(f, "none")
        } else {
            write!(f, "{}", set.join(", "))
        }
    }
}
