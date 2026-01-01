use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

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

/// Reads the process name from /proc/{pid}/comm
pub fn get_process_name(pid: u32) -> io::Result<String> {
    let path = PathBuf::from(format!("/proc/{}/comm", pid));
    let content = fs::read_to_string(path)?;
    Ok(content.trim().to_string())
}

/// Reads the command line from /proc/{pid}/cmdline
/// Arguments are separated by null bytes, so we replace them with spaces
pub fn get_process_cmdline(pid: u32) -> io::Result<String> {
    let path = PathBuf::from(format!("/proc/{}/cmdline", pid));
    let content = fs::read(path)?;

    // /proc/{pid}/cmdline contains arguments separated by null bytes
    // We'll replace null bytes with spaces to get a readable string
    let cmdline = content
        .split(|&b| b == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg))
        .collect::<Vec<_>>()
        .join(" ");

    Ok(cmdline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    #[test]
    fn test_get_process_name_current() {
        // This test might be flaky depending on how cargo test runs, but usually it should match "lanthorn" or "process"
        // or whatever the test runner process is named.
        // But simpler check: just ensure it doesn't fail for current PID
        let pid = process::id();
        let name = get_process_name(pid);
        assert!(name.is_ok());
        assert!(!name.unwrap().is_empty());
    }

    #[test]
    fn test_get_process_cmdline_current() {
        let pid = process::id();
        let cmdline = get_process_cmdline(pid);
        assert!(cmdline.is_ok());
        // The cmdline should contain "cargo" or the test binary name
        assert!(!cmdline.unwrap().is_empty());
    }

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
