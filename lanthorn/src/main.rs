use tokio::sync::RwLock;

use clap::Parser;
use log::info;
use std::collections::HashMap;
use std::sync::Arc;

mod monitor;
mod storage;
mod utils;

use monitor::DockerCache;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Disable TCP connection tracking through eBPF kprobe on tcp_connect
    #[arg(long, default_value_t = false)]
    disable_tcp_mon: bool,

    /// Disable docker container monitoring
    #[arg(long, default_value_t = false)]
    disable_docker_mon: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    env_logger::init();
    info!("Starting initialisation");

    storage::init().await?;

    let cache: DockerCache = Arc::new(RwLock::new(HashMap::new()));
    if !args.disable_docker_mon {
        monitor::run_docker_monitor(cache.clone()).await?;
    }

    if !args.disable_tcp_mon {
        monitor::run_tcp_monitor(cache.clone()).await?;
    }

    info!("All components initialised. Press Ctrl+C to exit.");

    // Wait for Ctrl+C signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
