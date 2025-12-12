#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct in_addr {
    pub s_addr: u32,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}

#[kprobe]
pub fn lanthorn(ctx: ProbeContext) -> u32 {
    match try_lanthorn(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_lanthorn(ctx: ProbeContext) -> Result<u32, u32> {
    let uaddr_ptr: *const sockaddr_in = match ctx.arg(1) {
        Some(ptr) => ptr,
        None => {
            info!(&ctx, "DEBUG: Failed to get arg(1)");
            return Err(1);
        }
    };

    let sockaddr: sockaddr_in = unsafe {
        match bpf_probe_read_kernel(uaddr_ptr) {
            Ok(s) => s,
            Err(e) => {
                // Log the actual error code from the kernel!
                info!(&ctx, "DEBUG: Read kernel failed: {}", e);
                return Err(1);
            }
        }
    };

    let ip = sockaddr.sin_addr.s_addr;
    let port = sockaddr.sin_port;
    let ip_host = u32::from_be(ip);
    let port_host = u16::from_be(port);

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    info!(
        &ctx,
        "PID: {} -> CONNECT: {}.{}.{}.{}:{}",
        pid,
        (ip_host >> 24) & 0xFF,
        (ip_host >> 16) & 0xFF,
        (ip_host >> 8) & 0xFF,
        ip_host & 0xFF,
        port_host
    );

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
