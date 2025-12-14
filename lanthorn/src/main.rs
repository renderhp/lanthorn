use tokio::sync::RwLock;

use clap::Parser;
use log::{error, info};
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
        let cache_for_docker = Arc::clone(&cache);
        tokio::spawn(async move {
            if let Err(e) = monitor::run_docker_monitor(cache_for_docker).await {
                error!("Docker monitor failed: {}", e);
            }
        });
    }

    if !args.disable_tcp_mon {
        let cache_for_bpf = Arc::clone(&cache);
        tokio::spawn(async move {
            if let Err(e) = monitor::run_tcp_monitor(cache_for_bpf).await {
                error!("TCP Monitor failed: {}", e);
            };
        });
    }

    info!("All components initialised. Press Ctrl+C to exit.");

    // Wait for Ctrl+C signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
