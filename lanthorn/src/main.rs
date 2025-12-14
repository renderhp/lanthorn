use clap::Parser;
use log::info;

mod monitor;
mod storage;
mod utils;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Disable TCP connection tracking through eBPF kprobe on tcp_connect
    #[arg(long, default_value_t = false)]
    disable_tcp: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    env_logger::init();
    info!("Starting initialisation");

    storage::init().await?;

    if !args.disable_tcp {
        monitor::run_monitor().await?;
    }

    info!("All components initialised. Press Ctrl+C to exit.");

    // Wait for Ctrl+C signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
