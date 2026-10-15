//! A packet parser written in Rust for studying network protocols,
//! low-level binary parsing, and the Rust programming language.
//!
//! This is a learning project, built as a foundation for security and
//! ethical hacking: each protocol layer lives in its own module, and
//! the parsing code is heavily commented, so the source doubles as
//! study notes.

#![warn(missing_docs)]

pub mod checksum;
pub mod errors;
pub mod frame;
pub mod hexdump;
pub mod layer2;
pub mod layer3;
pub mod samples;
