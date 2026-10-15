//! Hex dump formatting for raw bytes.

use std::fmt;

/// Displays a byte slice as a hexadecimal dump.
pub struct Hexdump<'a>(pub &'a [u8]);

impl fmt::Display for Hexdump<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, chunk) in self.0.chunks(16).enumerate() {
            write!(f, "{:04x}  ", i * 16)?;
            for (j, b) in chunk.iter().enumerate() {
                write!(f, "{b:02x} ")?;
                if j == 7 {
                    write!(f, " ")?;
                }
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
