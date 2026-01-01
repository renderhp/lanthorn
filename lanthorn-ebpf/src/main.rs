#![no_std]
#![no_main]

#[allow(
    clippy::all,
    dead_code,
    improper_ctypes_definitions,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unnecessary_transmutes,
    unsafe_op_in_unsafe_fn,
)]
#[rustfmt::skip]
mod vmlinux;

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
        generated::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
    },
    macros::{kprobe, map, uprobe, uretprobe},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::info;
use lanthorn_common::{ConnectEvent, DnsEvent, PendingDnsEntry};

use crate::vmlinux::{sock, sock_common, sockaddr_in, sockaddr_in6};

#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static mut DNS_EVENTS: RingBuf = RingBuf::with_byte_size(128 * 1024, 0);

/// Hash map to correlate getaddrinfo entry and return probes.
/// Key: u64 (pid_tgid), Value: PendingDnsEntry
#[map]
static mut PENDING_DNS: HashMap<u64, PendingDnsEntry> = HashMap::with_max_entries(1024, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// struct addrinfo - glibc userspace structure (not in kernel BTF)
/// This is a stable ABI structure used by getaddrinfo()
#[repr(C)]
struct addrinfo {
    ai_flags: i32,
    ai_family: i32,
    ai_socktype: i32,
    ai_protocol: i32,
    ai_addrlen: u32,
    _padding: u32, // Alignment padding on 64-bit
    ai_addr: *mut u8,
    ai_canonname: *mut u8,
    ai_next: *mut addrinfo,
}

#[kprobe]
pub fn kprobetcp(ctx: ProbeContext) -> u32 {
    match try_kprobetcp(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

fn try_kprobetcp(ctx: ProbeContext) -> Result<u32, i64> {
    // 1. Get the sock struct from the first argument
    let sock: *mut sock = ctx.arg(0).ok_or(1i64)?;

    // 2. Read the common socket data
    let sk_common = unsafe { bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common) }?;
    let family = sk_common.skc_family;

    // 3. Filter for IPv4/IPv6 only
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }
    // Read port - if this fails, return early before allocating ringbuf
    let dport =
        unsafe { bpf_probe_read_kernel(&sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport) }?;

    if let Some(mut ring_entry) = unsafe {
        let ptr = core::ptr::addr_of_mut!(EVENTS);
        (*ptr).reserve::<ConnectEvent>(0)
    } {
        // Get mutable reference to uninitialized memory
        let event = unsafe { &mut *ring_entry.as_mut_ptr() };

        // Fill Metadata
        let pid_tgid = bpf_get_current_pid_tgid();
        event.pid = (pid_tgid >> 32) as u32;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
        event.family = family;
        event.port = u16::from_be(dport);

        // Fill IP Address based on Family
        match family {
            AF_INET => {
                let dest_addr: u32 =
                    unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr };
                event.ip = [0; 16];
                event.ip[0..4].copy_from_slice(&dest_addr.to_ne_bytes());
            }
            AF_INET6 => {
                let dest_addr = sk_common.skc_v6_daddr;
                event.ip = unsafe { dest_addr.in6_u.u6_addr8 };
            }
            _ => {} // Should be unreachable due to check above
        }
        info!(&ctx, "Submitting new connection: pid={}", event.pid);

        // Submit to userspace - no error paths after reserve, so always submit
        ring_entry.submit(0);
    }

    Ok(0)
}

#[uprobe]
pub fn getaddrinfo_entry(ctx: ProbeContext) -> u32 {
    match try_getaddrinfo_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

fn try_getaddrinfo_entry(ctx: ProbeContext) -> Result<u32, i64> {
    // getaddrinfo signature: int getaddrinfo(const char *node, const char *service,
    //                                        const struct addrinfo *hints, struct addrinfo **res)
    let node_ptr: *const u8 = ctx.arg(0).ok_or(1i64)?;
    let res_ptr: u64 = ctx.arg::<u64>(3).ok_or(1i64)?; // struct addrinfo **res

    // Skip if node is NULL (happens when only service/port is provided)
    if node_ptr.is_null() {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();

    // Create pending entry to store in hash map
    let mut entry = PendingDnsEntry {
        domain: [0u8; 128],
        domain_len: 0,
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        res_ptr,
    };

    // Read domain name from userspace
    let bytes_read = unsafe { bpf_probe_read_user_str_bytes(node_ptr, &mut entry.domain) };

    match bytes_read {
        Ok(buf) => {
            entry.domain_len = buf.len() as u16;

            // Store in hash map for retrieval in return probe
            let pending_map = core::ptr::addr_of_mut!(PENDING_DNS);
            let _ = unsafe { (*pending_map).insert(&pid_tgid, &entry, 0) };

            info!(
                &ctx,
                "DNS entry: pid_tgid={}, domain_len={}", pid_tgid, entry.domain_len
            );
        }
        Err(_) => {
            // Failed to read domain, don't store entry
        }
    }

    Ok(0)
}

#[uretprobe]
pub fn getaddrinfo_return(ctx: RetProbeContext) -> u32 {
    match try_getaddrinfo_return(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

fn try_getaddrinfo_return(ctx: RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // Look up the pending entry from the hash map
    let pending_map = core::ptr::addr_of_mut!(PENDING_DNS);
    let entry = unsafe {
        match (*pending_map).get(&pid_tgid) {
            Some(e) => *e,        // Copy the entry
            None => return Ok(0), // No entry found (node was NULL), skip
        }
    };

    // Always remove the entry from the map to prevent leaks
    let _ = unsafe { (*pending_map).remove(&pid_tgid) };

    // Get return value (0 = success, non-zero = error)
    let ret_val: i32 = ctx.ret();

    // Handle getaddrinfo failure
    if ret_val != 0 {
        // TODO: Consider logging failed lookups for debugging
        return Ok(0);
    }

    // Read the result pointer: *res (dereference struct addrinfo **)
    let res_ptr_ptr = entry.res_ptr as *const *const addrinfo;
    let first_addrinfo_ptr: *const addrinfo = match unsafe { bpf_probe_read_user(res_ptr_ptr) } {
        Ok(ptr) => ptr,
        Err(_) => return Ok(0),
    };

    if first_addrinfo_ptr.is_null() {
        return Ok(0);
    }

    // Iterate through the addrinfo linked list (bounded loop for eBPF verifier)
    let mut current_ptr = first_addrinfo_ptr;

    // Max 16 addresses to satisfy eBPF verifier's bounded loop requirement
    for _ in 0..16u32 {
        if current_ptr.is_null() {
            break;
        }

        // Read current addrinfo struct
        let addrinfo_result: addrinfo = match unsafe { bpf_probe_read_user(current_ptr) } {
            Ok(ai) => ai,
            Err(_) => break,
        };

        // Only process IPv4 and IPv6
        let family = addrinfo_result.ai_family as u16;
        if family != AF_INET && family != AF_INET6 {
            // Move to next entry
            current_ptr = addrinfo_result.ai_next;
            continue;
        }

        // Reserve space in ring buffer for this address
        if let Some(mut ring_entry) = unsafe {
            let ptr = core::ptr::addr_of_mut!(DNS_EVENTS);
            (*ptr).reserve::<DnsEvent>(0)
        } {
            let event = unsafe { &mut *ring_entry.as_mut_ptr() };

            // Copy metadata from pending entry
            event.pid = (pid_tgid >> 32) as u32;
            event.cgroup_id = entry.cgroup_id;
            event.timestamp_ns = entry.timestamp_ns;
            event.domain = entry.domain;
            event.domain_len = entry.domain_len;
            event._padding = [0; 1];
            event.success = 1;
            event.family = family;
            event.resolved_ip = [0u8; 16];

            let mut valid = true;
            match family {
                AF_INET => {
                    // Read sockaddr_in
                    if let Ok(sockaddr) = unsafe {
                        bpf_probe_read_user(addrinfo_result.ai_addr as *const sockaddr_in)
                    } {
                        event.resolved_ip[0..4]
                            .copy_from_slice(&sockaddr.sin_addr.s_addr.to_ne_bytes());
                    } else {
                        valid = false;
                    }
                }
                AF_INET6 => {
                    // Read sockaddr_in6
                    if let Ok(sockaddr) = unsafe {
                        bpf_probe_read_user(addrinfo_result.ai_addr as *const sockaddr_in6)
                    } {
                        event.resolved_ip = unsafe { sockaddr.sin6_addr.in6_u.u6_addr8 };
                    } else {
                        valid = false;
                    }
                }
                _ => valid = false,
            }

            if valid {
                ring_entry.submit(0);
            } else {
                ring_entry.discard(0);
            }
        }

        // Move to next entry in linked list
        current_ptr = addrinfo_result.ai_next;
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
