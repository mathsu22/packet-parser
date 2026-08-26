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

### IPv4

- [x] Version
- [x] IHL
- [x] DSCP / ECN
- [x] Total Length
- [x] Identification
- [x] Flags / Fragment Offset
- [x] TTL
- [x] Protocol
- [x] Header Length
- [x] Header Checksum
- [x] Source Address
- [x] Destination Address

All header fields are parsed. Semantic validation (checksum verification,
buffer/length consistency checks) is the next step.

### Other protocols

- [ ] TCP header parsing
- [ ] ICMP header parsing


## Running

```bash
cargo run
```

## References

- [RFC 791 – Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)
- [RFC 6274 – Security Assessment of IPv4](https://www.rfc-editor.org/info/rfc6274/)
- [RFC 3168 – Explicit Congestion Notification (ECN)](https://www.rfc-editor.org/info/rfc3168/)
