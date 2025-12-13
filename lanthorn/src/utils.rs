use std::net::{Ipv4Addr, Ipv6Addr};

pub fn ip_to_string(family: u16, ip: [u8; 16]) -> Option<String> {
    match family {
        2 => {
            let ip: [u8; 4] = ip[0..4].try_into().ok()?;
            let ipv4 = Ipv4Addr::from(ip).to_string();
            Some(ipv4)
        }
        10 => {
            let ipv6 = Ipv6Addr::from(ip).to_string();
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

        let ipv6_arr: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05,
            0x00, 0x06,
        ];
        assert_eq!(
            ip_to_string(10, ipv6_arr),
            Some("2001:db8:1:2:3:4:5:6".to_string())
        );
    }
}
