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
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, generated::bpf_get_current_cgroup_id,
    },
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

use lanthorn_common::ConnectEvent;

#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

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

        info!(
            &ctx,
            "CONNECTION! pid: {}, cgroup_id: {}, port: {}", event.pid, event.cgroup_id, event.port
        );

        // Submit to userspace - no error paths after reserve, so always submit
        ring_entry.submit(0);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
