use std::{error::Error, process::ExitCode};

use packet_parser::{frame::Frame, hexdump::Hexdump, samples::PING_REQUEST};

fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("\n[ERROR]: {err}\n");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

// Dissects the hard-coded sample frame: prints the raw hex dump,
// then the layer tree via its Display.
fn run() -> Result<(), Box<dyn Error>> {
    let bytes = PING_REQUEST;

    println!("Frame: {} bytes ({} bits):", bytes.len(), 8 * bytes.len());
    println!("{}", Hexdump(bytes));
    print!("{}", Frame::parse(bytes)?);
    Ok(())
}
