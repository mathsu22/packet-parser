//! Wireshark-style text formatting for [`Ipv4Header`]
//! (or at least an attempt at it).

use crate::ipv4::{
    dscp_ecn::{dscp_name, ecn_keyword},
    packet::Ipv4Header,
};
use std::fmt;

impl fmt::Display for Ipv4Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reserved_warning = if self.flags.is_anomalous() {
            "- [Expert Info (Warning/Protocol): Reserved bit is set (must be zero)]"
        } else {
            ""
        };

        write!(
            f,
            "\
            Version: {} \n\
            Header Length: {} bytes ({}) \n\
            Differentiated Services Field: {:#04x} (DSCP: {}, ECN: {}) \n\
            Total Length: {} \n\
            Identification: {:#06x} ({}) \n\
            Flags: {:#04x}, {} {}\n\
            Fragment Offset: {} \n\
            Time to Live: {} \n\
            Protocol: {} ({})\n\
            Header Checksum: {:#06x} \n\
            Source Address: {} \n\
            Destination Address: {} \
            ",
            self.version,
            self.ihl * 4,
            self.ihl,
            (self.dscp << 2) | self.ecn,
            dscp_name(self.dscp),
            ecn_keyword(self.ecn),
            self.total_length,
            self.identification,
            self.identification,
            self.flags.as_byte(),
            self.flags,
            reserved_warning,
            self.fragment_offset,
            self.ttl,
            self.protocol,
            self.protocol.value(),
            self.checksum,
            self.source_address,
            self.destination_address,
        )
    }
}
