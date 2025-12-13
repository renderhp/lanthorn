use aya::{maps::RingBuf, programs::KProbe};
use aya_log::EbpfLogger;
use clap::Parser;
use lanthorn_common::ConnectEvent;
use log::{info, warn};

mod ebpf_handler;
mod utils;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _args = Args::parse();
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

                ebpf_handler::handle_event(event).await;
            }
            None => {
                // No events available, sleep briefly to avoid busy-waiting
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}
