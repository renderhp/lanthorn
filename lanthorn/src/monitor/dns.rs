use std::time::Duration;

use aya::{Ebpf, maps::RingBuf, programs::UProbe};
use lanthorn_common::DnsEvent;
use log::{info, warn};
use sqlx::SqlitePool;
use tokio::io::unix::AsyncFd;

use crate::{
    monitor::{
        DockerCache,
        dns_cache::{DnsCache, PendingDnsCache, PendingDnsQuery, evict_expired},
    },
    storage,
};

const DNS_CACHE_TTL_SECS: u64 = 300; // 5 minutes default TTL
const PENDING_DNS_WINDOW_NS: u64 = 30_000_000_000; // 30 seconds

pub async fn run_dns_monitor(
    pool: SqlitePool,
    dns_cache: DnsCache,
    pending_dns_cache: PendingDnsCache,
    docker_cache: DockerCache,
) -> Result<(), anyhow::Error> {
    info!("Starting DNS resolution monitor...");

    // Load eBPF program
    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lanthorn"
    )))?;

    // Attach uprobe to getaddrinfo in libc
    // Try common libc locations
    let libc_paths = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/usr/lib/libc.so.6",
        "/lib64/libc.so.6",
    ];

    let program: &mut UProbe = bpf.program_mut("getaddrinfo_entry").unwrap().try_into()?;
    program.load()?;

    let mut attached = false;
    for path in &libc_paths {
        if std::path::Path::new(path).exists() {
            // For uprobe, we need to attach with offset None (auto-resolve symbol)
            // and pid None (attach to all processes)
            match program.attach("getaddrinfo", path, None, None) {
                Ok(_) => {
                    info!("Attached DNS monitor to {} @ getaddrinfo", path);
                    attached = true;
                    break;
                }
                Err(e) => {
                    warn!("Failed to attach to {}: {}", path, e);
                }
            }
        }
    }

    if !attached {
        return Err(anyhow::anyhow!(
            "Failed to attach to any libc path. Tried: {:?}",
            libc_paths
        ));
    }

    let ring_buf = RingBuf::try_from(bpf.take_map("DNS_EVENTS").unwrap())?;
    let mut ring_buf_poll = AsyncFd::new(ring_buf).unwrap();

    // Spawn cache eviction task for DNS cache
    let dns_cache_for_eviction = dns_cache.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let evicted = evict_expired(&dns_cache_for_eviction, DNS_CACHE_TTL_SECS).await;
            if evicted > 0 {
                info!("Evicted {} expired DNS cache entries", evicted);
            }
        }
    });

    // Spawn pending DNS cleanup task
    let pending_cache_for_cleanup = pending_dns_cache.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            cleanup_pending_dns(&pending_cache_for_cleanup).await;
        }
    });

    info!("Waiting for DNS events...");

    loop {
        let mut guard = ring_buf_poll.readable_mut().await.unwrap();

        while let Some(item) = guard.get_inner_mut().next() {
            let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const DnsEvent) };
            handle_dns_event(
                pool.clone(),
                event,
                pending_dns_cache.clone(),
                docker_cache.clone(),
            )
            .await;
        }

        guard.clear_ready();
    }
}

async fn handle_dns_event(
    pool: SqlitePool,
    event: DnsEvent,
    pending_cache: PendingDnsCache,
    docker_cache: DockerCache,
) {
    // Extract domain name from fixed-size buffer
    let domain_bytes = &event.domain[..event.domain_len as usize];
    let domain = match std::str::from_utf8(domain_bytes) {
        Ok(s) => s.to_string(),
        Err(e) => {
            warn!("Invalid UTF-8 in domain name: {}", e);
            return;
        }
    };

    info!(
        "DNS query: pid={}, cgroup={}, domain={}",
        event.pid, event.cgroup_id, domain
    );

    // Look up Docker container info
    let docker_info = docker_cache.read().await.get(&event.cgroup_id).cloned();
    if let Some(ref info) = docker_info {
        info!(
            "  Container: {:?}, Image: {:?}",
            info.names.as_ref().and_then(|v| v.first()),
            info.image
        );
    }

    // Store in pending DNS cache for later correlation with TCP connections
    let query = PendingDnsQuery {
        domain: domain.clone(),
        timestamp_ns: event.timestamp_ns,
        _cgroup_id: event.cgroup_id,
    };

    let mut cache = pending_cache.write().await;
    cache.entry(event.pid).or_insert_with(Vec::new).push(query);

    // Keep only recent queries (within 30 seconds)
    if let Some(queries) = cache.get_mut(&event.pid) {
        let cutoff = event.timestamp_ns.saturating_sub(PENDING_DNS_WINDOW_NS);
        queries.retain(|q| q.timestamp_ns > cutoff);
    }

    // Optionally store DNS event in database for debugging/auditing
    let container_name = docker_info
        .as_ref()
        .and_then(|d| d.names.clone())
        .and_then(|v| v.first().cloned());
    let container_id = docker_info.as_ref().map(|d| d.id.clone());
    let image_name = docker_info.as_ref().and_then(|d| d.image.clone());

    let _ = storage::insert_dns_event(
        &pool,
        &domain,
        event.pid,
        Some(event.cgroup_id),
        container_id,
        container_name,
        image_name,
    )
    .await;
}

async fn cleanup_pending_dns(pending_cache: &PendingDnsCache) {
    let mut cache = pending_cache.write().await;
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let cutoff = now_ns.saturating_sub(PENDING_DNS_WINDOW_NS);

    // Remove entries with no recent queries
    cache.retain(|_pid, queries| {
        queries.retain(|q| q.timestamp_ns > cutoff);
        !queries.is_empty()
    });
}
