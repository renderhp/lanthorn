use aya::{Ebpf, maps::RingBuf, programs::KProbe};
use aya_log::EbpfLogger;
use lanthorn_common::ConnectEvent;
use log::{info, warn};
use tokio::io::unix::AsyncFd;

use crate::utils::ip_to_string;

pub async fn run_monitor() -> Result<(), anyhow::Error> {
    info!("Starting TCP connection monitor...");

    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lanthorn"
    )))?;

    match EbpfLogger::init(&mut bpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut KProbe = bpf.program_mut("kprobetcp").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_connect", 0)?;

    let ring_buf = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    let mut ring_buf_poll = AsyncFd::new(ring_buf).unwrap();
    info!("Waiting for events...");

    tokio::spawn(async move {
        // Without the line below bpf gets dropped and no events are being registered
        let _keep_bpf_alive = bpf;

        loop {
            let mut guard = ring_buf_poll.readable_mut().await.unwrap();

            while let Some(item) = guard.get_inner_mut().next() {
                let event =
                    unsafe { std::ptr::read_unaligned(item.as_ptr() as *const ConnectEvent) };
                handle_event(event).await;
            }

            guard.clear_ready();
        }
    });

    Ok(())
}

async fn handle_event(event: ConnectEvent) {
    info!(
        "Connection: PID={}, Port={}, Family={}, CGroup={}",
        event.pid, event.port, event.family, event.cgroup_id
    );

    if let Some(ip_string) = ip_to_string(event.family, event.ip) {
        info!("{}", ip_string);
    }
}
