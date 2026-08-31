//! Byte 1 of the IPv4 header: the Differentiated Services (DS) field,
//! split into DSCP (6 bits) + ECN (2 bits). In RFC 791 this was the
//! "Type of Service" byte; RFC 2474 redefined it.
//!
//! Registry: <https://www.iana.org/assignments/dscp-registry/>

/// Maps a DSCP codepoint (0..=63) to its IANA registry name
/// (`CS0`, `EF`, `AF41`, ...). Unmapped values return "Unknown".
// TODO: Complete the DSCP value mapping.
pub fn dscp_name(dscp_value: u8) -> &'static str {
    match dscp_value {
        0 => "CS0",
        8 => "CS1",
        16 => "CS2",
        _ => "Unknown",
    }
}

/// Maps the 2-bit ECN value (0..=3) to its RFC 3168 keyword.
pub fn ecn_keyword(ecn_value: u8) -> &'static str {
    match ecn_value {
        0 => "Not-ECT", // (Not ECN-Capable Transport)
        1 => "ECT(1)",  // (ECN-Capable Transport(1))
        2 => "ECT(0)",  //(ECN-Capable Transport(0))
        3 => "CE",      //(Congestion Experienced)
        _ => "Unknown",
    }
}
