use aya::{maps::RingBuf, programs::KProbe};
use aya_log::EbpfLogger;
use lanthorn_common::ConnectEvent;
use log::{info, warn};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lanthorn"
    )))?;
    match EbpfLogger::init(&mut bpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
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

    let mut ring_buf = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    info!("Waiting for events...");

    // Poll for events in a loop
    loop {
        match ring_buf.next() {
            Some(item) => {
                // Parse the event
                let event = unsafe {
                    // Cast the bytes to your ConnectEvent struct
                    std::ptr::read_unaligned(item.as_ptr() as *const ConnectEvent)
                };

                handle_event(event).await;
            }
            None => {
                // No events available, sleep briefly to avoid busy-waiting
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

async fn handle_event(event: ConnectEvent) {
    info!(
        "Connection: PID={}, Port={}, Family={}, CGroup={}",
        event.pid, event.port, event.family, event.cgroup_id
    );

    // Pretty print IP address
    match event.family {
        2 => {
            // AF_INET
            info!(
                "  IPv4: {}.{}.{}.{}",
                event.ip[0], event.ip[1], event.ip[2], event.ip[3]
            );
        }
        10 => {
            // AF_INET6
            info!(
                "  IPv6: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                event.ip[0],
                event.ip[1],
                event.ip[2],
                event.ip[3],
                event.ip[4],
                event.ip[5],
                event.ip[6],
                event.ip[7],
                event.ip[8],
                event.ip[9],
                event.ip[10],
                event.ip[11],
                event.ip[12],
                event.ip[13],
                event.ip[14],
                event.ip[15]
            );
        }
        _ => {}
    }
}
