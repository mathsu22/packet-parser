# packet-parser

A packet parser written in Rust for studying network protocols,
low-level binary parsing, and the Rust programming language.

> **Work in progress.** This is a learning project — code, structure,
> and error handling are evolving as I study each protocol layer.
> Feedback and suggestions are welcome!

## Why

I'm studying networking, systems programming, and Rust to build a
strong foundation for security and ethical hacking.

## What it does so far

### Layer 2

- [x] Ethernet II

### Layer 3

- [x] IPv4 (full header + anomaly detection + checksum verification)
- [x] ICMP (echo messages: common header, echo body + data, truncation anomaly)

### Layer 4

- [ ] TCP
- [ ] UDP

## Running

```bash
cargo run
```

## Documentation

Protocol references (RFCs, IEEE standards, IANA registries) live in each
module's documentation. Browse them with:

```bash
cargo doc --open
```
