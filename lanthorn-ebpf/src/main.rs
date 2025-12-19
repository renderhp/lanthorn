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

use crate::vmlinux::{sock, sock_common};

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user_str_bytes,
        generated::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
    },
    macros::{kprobe, map, uprobe},
    maps::RingBuf,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

use lanthorn_common::{ConnectEvent, DnsEvent};

#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static mut DNS_EVENTS: RingBuf = RingBuf::with_byte_size(128 * 1024, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

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
    // getaddrinfo signature: int getaddrinfo(const char *node, ...)
    // First argument is domain name (const char*)
    let node_ptr: *const u8 = ctx.arg(0).ok_or(1i64)?;

    // Skip if node is NULL (happens when only service/port is provided)
    if node_ptr.is_null() {
        return Ok(0);
    }

    if let Some(mut ring_entry) = unsafe {
        let ptr = core::ptr::addr_of_mut!(DNS_EVENTS);
        (*ptr).reserve::<DnsEvent>(0)
    } {
        let event = unsafe { &mut *ring_entry.as_mut_ptr() };

        // Fill metadata first
        let pid_tgid = bpf_get_current_pid_tgid();
        event.pid = (pid_tgid >> 32) as u32;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.timestamp_ns = unsafe { bpf_ktime_get_ns() };

        // Read domain name from userspace (this also zero-initializes the buffer)
        let bytes_read = unsafe {
            bpf_probe_read_user_str_bytes(node_ptr as *const u8, &mut event.domain)
        };

        match bytes_read {
            Ok(buf) => {
                // buf.len() already excludes the null terminator
                event.domain_len = buf.len() as u16;
                info!(&ctx, "DNS query: pid={}, domain_len={}", event.pid, event.domain_len);
                ring_entry.submit(0);
            }
            Err(_) => {
                // Failed to read domain, discard the ring entry
                ring_entry.discard(0);
            }
        }
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
