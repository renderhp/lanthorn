use std::{collections::HashMap, sync::Arc};

use clap::Parser;
use log::{error, info, warn};
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
        info!("Threat feeds disabled, loading existing cache if any...");
        // Even if disabled, we should try to load what we have in DB
        // But if disabled typically means "don't use it", maybe we skip loading too?
        // The prompt said: "no updates for now, but design it with updates in mind... application should fail to start unless a flag to disable threat feeds is provided"
        // It implies if I disable it, I probably don't care about threats.
        // However, if I have old data, might as well use it?
        // Let's load cache regardless if we can, but only fetch if enabled.
        // Actually, if disabled, maybe we shouldn't even check?
        // Let's stick to: fetch if enabled. If fetch fails, die.
        // If disabled, just don't fetch.
        // But we still need the engine for the monitor.
        // Let's load cache.
        if let Err(e) = threat_engine.load_cache().await {
            warn!("Failed to load threat cache: {}", e);
        }
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

    info!("All components initialised. Press Ctrl+C to exit.");

    // Wait for Ctrl+C signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
