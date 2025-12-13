pub fn ip_to_string(family: u16, ip: [u8; 16]) -> Option<String> {
    match family {
        2 => {
            let ipv4 = ip[0..4]
                .iter()
                .map(|b| format!("{}", b))
                .collect::<Vec<_>>()
                .join(".");
            Some(ipv4)
        }
        10 => {
            let ipv6 = ip
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":");
            Some(ipv6)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_to_string() {
        let ipv4_arr = [127, 12, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] as [u8; 16];
        assert_eq!(ip_to_string(2, ipv4_arr), Some("127.12.1.1".to_string()));
    }
}
