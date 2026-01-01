#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub pid: u32,
    pub cgroup_id: u64,
    pub timestamp_ns: u64,
    pub ip: [u8; 16], // Unified storage for IPv4 (mapped) and IPv6
    pub port: u16,
    pub family: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub pid: u32,
    pub cgroup_id: u64,
    pub timestamp_ns: u64,
    pub domain: [u8; 128], // Fixed-size domain name (null-terminated) - reduced for eBPF verifier
    pub domain_len: u16,   // Actual length of domain string
    pub family: u16,       // AF_INET (2) or AF_INET6 (10)
    pub resolved_ip: [u8; 16], // Resolved IP address (IPv4 in first 4 bytes, or full IPv6)
    pub success: u8,       // 1 if resolution succeeded, 0 if failed
    pub _padding: [u8; 1], // Alignment padding
}

/// Internal struct for BPF hash map - stores entry data for correlation with return probe.
/// Not sent to userspace, only used within eBPF program.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingDnsEntry {
    pub domain: [u8; 128],
    pub domain_len: u16,
    pub cgroup_id: u64,
    pub timestamp_ns: u64,
    pub res_ptr: u64, // Pointer to struct addrinfo** (4th arg of getaddrinfo)
}
