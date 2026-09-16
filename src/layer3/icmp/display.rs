//! Wireshark-style text formatting for [`IcmpMessage`].

use crate::{
    checksum::ChecksumStatus,
    layer3::icmp::message::{IcmpBody, IcmpMessage},
};
use std::fmt;

impl<'a> fmt::Display for IcmpMessage<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Internet Control Message Protocol")?;

        writeln!(f, "Type: {} ({})", self.type_, self.type_.value())?;

        writeln!(f, "Code: {}", self.code)?;

        writeln!(
            f,
            "Checksum: {:#06x} [{}]",
            self.checksum_, self.checksum_status
        )?;
        self.write_checksum_status(f)?;

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

                Self::write_data(f, echo.data)?;
            }
            IcmpBody::Echo(None) => {}
            IcmpBody::Other(raw_body) => Self::write_data(f, raw_body)?,
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

    fn write_checksum_status(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.checksum_status {
            ChecksumStatus::Bad => writeln!(f, "[Checksum status: Bad]"),
            ChecksumStatus::NotVerifiable => writeln!(f, "[Checksum status: Unverified]"),
            ChecksumStatus::Good => writeln!(f, "[Checksum status: Good]"),
        }
    }

    fn write_data(f: &mut fmt::Formatter<'_>, data: &[u8]) -> fmt::Result {
        writeln!(f, "Data ({} bytes)\n", data.len())?;

        for (i, chunk) in data.chunks(16).enumerate() {
            write!(f, "{:04x}  ", i * 16)?;
            for b in chunk {
                write!(f, "{:02x} ", b)?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
