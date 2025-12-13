#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub pid: u32,
    pub cgroup_id: u64,
    pub ip: [u8; 16], // Unified storage for IPv4 (mapped) and IPv6
    pub port: u16,
    pub family: u16,
}
