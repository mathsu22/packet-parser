//! Wireshark-style text formatting for [`IcmpMessage`].

use crate::layer3::icmp::message::{IcmpBody, IcmpMessage};
use std::fmt;

impl<'a> fmt::Display for IcmpMessage<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Type: {} ({})", self.type_, self.type_.value())?;

        writeln!(f, "Code: {}", self.code)?;

        writeln!(
            f,
            "Checksum: {:#06x} [{}]",
            self.checksum_, self.checksum_status
        )?;

        match self.body {
            IcmpBody::Echo(Some(echo)) => {
                writeln!(
                    f,
                    "Identifier: {} ({:#06x})",
                    echo.identifier, echo.identifier
                )?;

                writeln!(
                    f,
                    "Sequence Number: {} ({:#06x})",
                    echo.sequence_number, echo.sequence_number
                )?;

                writeln!(f, "Data ({} bytes)\n", echo.data.len())?;

                for (i, chunk) in echo.data.chunks(16).enumerate() {
                    write!(f, "{:04x}  ", i * 16)?;
                    for b in chunk.iter() {
                        write!(f, "{:02x} ", b)?;
                    }
                    writeln!(f)?;
                }
            }
            IcmpBody::Echo(None) => {}
            IcmpBody::Other => {}
        }

        self.write_anomalies(f)
    }
}

impl<'a> IcmpMessage<'a> {
    fn write_anomalies(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for anomaly in &self.anomalies {
            writeln!(f, "[Expert Info: {anomaly}]")?;
        }
        Ok(())
    }
}
