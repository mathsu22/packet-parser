fn main() {
    if let Err(err) = packet_parser::run() {
        eprintln!("\n[ERROR]: {}\n", err);
        std::process::exit(1);
    }
}
