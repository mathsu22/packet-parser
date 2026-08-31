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

All header fields are parsed, with non-fatal anomaly detection (Wireshark-style"Expert Info" warnings) for malformed or inconsistent headers — invalid IHL,length contradictions, truncated captures, reserved bits. The header checksumis verified (RFC 1071) and reported inline on the checksum line — correct /incorrect / unverified — rather than as an anomaly. Every path is coveredby tests.

### Other protocols

- [ ] ICMP header parsing
- [ ] TCP header parsing


## Running

```bash
cargo run
```

## References

- [RFC 791 – Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)
- [RFC 6274 – Security Assessment of IPv4](https://www.rfc-editor.org/info/rfc6274/)
- [RFC 1071 – Computing the Internet Checksum](https://www.rfc-editor.org/info/rfc1071)
