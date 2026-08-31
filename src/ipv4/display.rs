//! Wireshark-style text formatting for [`Ipv4Header`]
//! (or at least an attempt at it).

use std::fmt;

use crate::ipv4::{
    anomalies::HeaderField,
    dscp_ecn::{dscp_name, ecn_keyword},
    packet::Ipv4Header,
};

impl fmt::Display for Ipv4Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Version: {}", self.version)?;

        writeln!(f, "Header Length: {} bytes ({})", self.ihl * 4, self.ihl)?;
        self.write_field_anomalies(f, HeaderField::HeaderLength)?;

        writeln!(
            f,
            "Differentiated Services Field: {:#04x} (DSCP: {}, ECN: {})",
            (self.dscp << 2) | self.ecn,
            dscp_name(self.dscp),
            ecn_keyword(self.ecn),
        )?;

        writeln!(f, "Total Length: {}", self.total_length)?;
        self.write_field_anomalies(f, HeaderField::TotalLength)?;

        writeln!(
            f,
            "Identification: {:#06x} ({})",
            self.identification, self.identification
        )?;

        writeln!(f, "Flags: {:#04x}, {}", self.flags.as_byte(), self.flags)?;
        self.write_field_anomalies(f, HeaderField::Flags)?;

        writeln!(f, "Fragment Offset: {}", self.fragment_offset)?;
        writeln!(f, "Time to Live: {}", self.ttl)?;
        writeln!(f, "Protocol: {} ({})", self.protocol, self.protocol.value())?;
        writeln!(
            f,
            "Header Checksum: {:#06x} [{}]",
            self.header_checksum, self.checksum_status
        )?;
        writeln!(f, "Source Address: {}", self.source_address)?;
        write!(f, "Destination Address: {}", self.destination_address)?;

        Ok(())
    }
}

impl Ipv4Header {
    fn write_field_anomalies(
        &self,
        f: &mut fmt::Formatter<'_>,
        target: HeaderField,
    ) -> fmt::Result {
        for anomaly in self.anomalies.iter().filter(|a| a.field() == target) {
            writeln!(f, "   [Expert Info: {anomaly}]")?;
        }
        Ok(())
    }
}
