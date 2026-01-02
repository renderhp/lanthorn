use std::{collections::HashMap, sync::Arc, time::Duration};

use clap::Parser;
use log::{error, info};
use tokio::sync::RwLock;

mod monitor;
mod storage;
mod utils;

use monitor::{DnsCache, DockerCache, ThreatEngine};

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

    /// Disable Threat Feeds
    #[arg(long, default_value_t = false)]
    disable_threat_feeds: bool,

    /// Path to the sqlite DB file. Default is lanthorn.db
    #[arg(long, default_value = "lanthorn.db")]
    db_path: String,

    /// Data retention period in days. Events older than this will be deleted.
    /// Set to 0 to disable retention (keep events forever). Default is 3 days.
    #[arg(long, default_value_t = 3)]
    retention_days: u64,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    env_logger::init();
    info!("Starting initialisation");

    let pool = storage::init(&args.db_path).await?;

    // Initialise Threat Engine
    let threat_engine = ThreatEngine::new(pool.clone());
    if !args.disable_threat_feeds {
        info!("Fetching threat feeds...");
        if let Err(e) = threat_engine.fetch_feeds().await {
            error!("Failed to fetch threat feeds: {}", e);
            error!("Please relaunch with --disable-threat-feeds to skip this check.");
            return Err(e);
        }
    } else {
        info!("Threat feeds disabled. Skipping cache load.");
    }

    // Create shared caches
    let docker_cache: DockerCache = Arc::new(RwLock::new(HashMap::new()));
    let dns_cache: DnsCache = Arc::new(RwLock::new(HashMap::new()));

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
        let docker_cache_clone = Arc::clone(&docker_cache);

        tokio::spawn(async move {
            if let Err(e) =
                monitor::run_dns_monitor(pool_clone, dns_cache_clone, docker_cache_clone).await
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
        let threat_engine_clone = threat_engine.clone();

        tokio::spawn(async move {
            if let Err(e) = monitor::run_tcp_monitor(
                pool_clone,
                docker_cache_clone,
                dns_cache_clone,
                threat_engine_clone,
            )
            .await
            {
                error!("TCP Monitor failed: {}", e);
            };
        });
    }

    // Start retention cleanup task (runs immediately, then every hour)
    let retention_days = args.retention_days;
    if retention_days > 0 {
        info!("Data retention enabled: {} days", retention_days);
        let pool_clone = pool.clone();
        tokio::spawn(async move {
            let cleanup_interval = Duration::from_secs(60 * 60); // 1 hour
            loop {
                if let Err(e) = storage::delete_old_events(&pool_clone, retention_days).await {
                    error!("Retention cleanup failed: {}", e);
                }
                tokio::time::sleep(cleanup_interval).await;
            }
        });
    } else {
        info!("Data retention disabled (keeping events forever)");
    }

    info!("All components initialised. Press Ctrl+C to exit.");

    // Wait for Ctrl+C signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
