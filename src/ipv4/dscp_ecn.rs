//https://www.iana.org/assignments/dscp-registry

// TODO: Complete the DSCP value mapping.
pub fn dscp_name(dscp_value: u8) -> &'static str {
    match dscp_value {
        0 => "CS0",
        8 => "CS1",
        16 => "CS2",
        _ => "Unknown",
    }
}

pub fn ecn_keyword(ecn_value: u8) -> &'static str {
    match ecn_value {
        0 => "Not-ECT", // (Not ECN-Capable Transport)
        1 => "ECT(1)",  // (ECN-Capable Transport(1))
        2 => "ECT(0)",  //(ECN-Capable Transport(0))
        3 => "CE",      //(Congestion Experienced)
        _ => "Unknown",
    }
}
