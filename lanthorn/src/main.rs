use std::{collections::HashMap, sync::Arc};

use clap::Parser;
use log::{error, info};
use tokio::sync::RwLock;

mod monitor;
mod storage;
mod utils;

use monitor::{DnsCache, DockerCache, PendingDnsCache};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Disable TCP connection tracking through eBPF kprobe on tcp_connect
    #[arg(long, default_value_t = false)]
    disable_tcp_mon: bool,

    /// Disable docker container monitoring
    #[arg(long, default_value_t = false)]
    disable_docker_mon: bool,

    /// Disable DNS resolution tracking
    #[arg(long, default_value_t = false)]
    disable_dns_mon: bool,

    /// Path to the sqlite DB file. Default is lanthorn.db
    #[arg(long, default_value = "lanthorn.db")]
    db_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    env_logger::init();
    info!("Starting initialisation");

    let pool = storage::init(&args.db_path).await?;

    // Create shared caches
    let docker_cache: DockerCache = Arc::new(RwLock::new(HashMap::new()));
    let dns_cache: DnsCache = Arc::new(RwLock::new(HashMap::new()));
    let pending_dns_cache: PendingDnsCache = Arc::new(RwLock::new(HashMap::new()));

    // Start Docker monitor
    if !args.disable_docker_mon {
        let cache_for_docker = Arc::clone(&docker_cache);
        tokio::spawn(async move {
            if let Err(e) = monitor::run_docker_monitor(cache_for_docker).await {
                error!("Docker monitor failed: {}", e);
            }
        });
    }

    // Start DNS monitor
    if !args.disable_dns_mon {
        let pool_clone = pool.clone();
        let dns_cache_clone = Arc::clone(&dns_cache);
        let pending_cache_clone = Arc::clone(&pending_dns_cache);
        let docker_cache_clone = Arc::clone(&docker_cache);

        tokio::spawn(async move {
            if let Err(e) = monitor::run_dns_monitor(
                pool_clone,
                dns_cache_clone,
                pending_cache_clone,
                docker_cache_clone,
            )
            .await
            {
                error!("DNS monitor failed: {}", e);
            }
        });
    }

    // Start TCP monitor
    if !args.disable_tcp_mon {
        let pool_clone = pool.clone();
        let docker_cache_clone = Arc::clone(&docker_cache);
        let dns_cache_clone = Arc::clone(&dns_cache);
        let pending_cache_clone = Arc::clone(&pending_dns_cache);

        tokio::spawn(async move {
            if let Err(e) = monitor::run_tcp_monitor(
                pool_clone,
                docker_cache_clone,
                dns_cache_clone,
                pending_cache_clone,
            )
            .await
            {
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
