use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aya::{Ebpf, maps::RingBuf, programs::UProbe};
use lanthorn_common::DnsEvent;
use log::{debug, info, warn};
use sqlx::SqlitePool;
use tokio::io::unix::AsyncFd;

use crate::{
    monitor::{
        DockerCache,
        dns_cache::{DnsCache, DnsCacheEntry, evict_expired, insert_mapping},
    },
    storage,
};

const DNS_CACHE_TTL_SECS: u64 = 300; // 5 minutes default TTL
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

pub async fn run_dns_monitor(
    pool: SqlitePool,
    dns_cache: DnsCache,
    docker_cache: DockerCache,
) -> Result<(), anyhow::Error> {
    info!("Starting DNS resolution monitor...");

    // Load eBPF program
    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lanthorn"
    )))?;

    // Common libc locations
    let libc_paths = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/usr/lib/libc.so.6",
        "/lib64/libc.so.6",
    ];

    // Load and attach entry probe
    let entry_program: &mut UProbe = bpf.program_mut("getaddrinfo_entry").unwrap().try_into()?;
    entry_program.load()?;

    let mut attached_path: Option<&str> = None;
    for path in &libc_paths {
        if std::path::Path::new(path).exists() {
            match entry_program.attach("getaddrinfo", path, None, None) {
                Ok(_) => {
                    info!("Attached DNS entry probe to {} @ getaddrinfo", path);
                    attached_path = Some(path);
                    break;
                }
                Err(e) => {
                    warn!("Failed to attach entry probe to {}: {}", path, e);
                }
            }
        }
    }

    let Some(libc_path) = attached_path else {
        return Err(anyhow::anyhow!(
            "Failed to attach entry probe to any libc path. Tried: {:?}",
            libc_paths
        ));
    };

    // Load and attach return probe (uretprobe) to the same path
    let return_program: &mut UProbe = bpf.program_mut("getaddrinfo_return").unwrap().try_into()?;
    return_program.load()?;
    return_program.attach("getaddrinfo", libc_path, None, None)?;
    info!("Attached DNS return probe to {} @ getaddrinfo", libc_path);

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

    info!("Waiting for DNS events...");

    loop {
        let mut guard = ring_buf_poll.readable_mut().await.unwrap();

        while let Some(item) = guard.get_inner_mut().next() {
            let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const DnsEvent) };
            handle_dns_event(pool.clone(), event, dns_cache.clone(), docker_cache.clone()).await;
        }

        guard.clear_ready();
    }
}

pub(crate) async fn handle_dns_event(
    pool: SqlitePool,
    event: DnsEvent,
    dns_cache: DnsCache,
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

    // Parse resolved IP if successful
    let resolved_ip: Option<IpAddr> = if event.success == 1 {
        match event.family {
            AF_INET => {
                let addr_bytes: [u8; 4] = event.resolved_ip[0..4].try_into().unwrap();
                Some(IpAddr::V4(Ipv4Addr::from(addr_bytes)))
            }
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(event.resolved_ip))),
            _ => None,
        }
    } else {
        None
    };

    if let Some(ip) = &resolved_ip {
        info!(
            "DNS resolution: pid={}, domain={} -> {}",
            event.pid, domain, ip
        );

        // Insert into DNS cache directly (no more pending cache!)
        // Use wall clock time for TTL expiration (eBPF timestamp is kernel monotonic time)
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let entry = DnsCacheEntry {
            domain: domain.clone(),
            timestamp_ns: now_ns,
        };
        insert_mapping(&dns_cache, *ip, entry).await;
    } else {
        debug!(
            "DNS query (no result): pid={}, domain={}, success={}",
            event.pid, domain, event.success
        );
        // TODO: Consider logging failed lookups to database for debugging
    }

    // Look up Docker container info
    let docker_info = docker_cache.read().await.get(&event.cgroup_id).cloned();
    if let Some(ref info) = docker_info {
        info!(
            "  Container: {:?}, Image: {:?}",
            info.names.as_ref().and_then(|v| v.first()),
            info.image
        );
    }

    // Store DNS event in database (with resolved IP now)
    let container_name = docker_info
        .as_ref()
        .and_then(|d| d.names.clone())
        .and_then(|v| v.first().cloned());
    let container_id = docker_info.as_ref().map(|d| d.id.clone());
    let image_name = docker_info.as_ref().and_then(|d| d.image.clone());

    let _ = storage::insert_dns_event(
        &pool,
        &domain,
        resolved_ip.as_ref().map(|ip| ip.to_string()).as_deref(),
        event.pid,
        Some(event.cgroup_id),
        container_id,
        container_name,
        image_name,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use sqlx::Row;
    use crate::monitor::dns_cache::lookup_domain;
    use crate::monitor::docker::MonitoredContainer;

    async fn setup_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn test_handle_dns_event_success() {
        let pool = setup_db().await;
        let dns_cache = Arc::new(RwLock::new(HashMap::new()));
        let docker_cache = Arc::new(RwLock::new(HashMap::new()));

        // Create a fake container in cache
        let container = MonitoredContainer {
            id: "test_container_id".to_string(),
            names: Some(vec!["test_container_name".to_string()]),
            image: Some("test_image".to_string()),
            pid: 100,
            cgroup_id: 12345,
        };
        docker_cache.write().await.insert(12345, container);

        // Construct DnsEvent
        let domain_str = "example.com";
        let mut domain = [0u8; 128];
        domain[..domain_str.len()].copy_from_slice(domain_str.as_bytes());

        // IPv4: 1.2.3.4
        let mut resolved_ip = [0u8; 16];
        resolved_ip[0] = 1;
        resolved_ip[1] = 2;
        resolved_ip[2] = 3;
        resolved_ip[3] = 4;

        let event = DnsEvent {
            pid: 100,
            cgroup_id: 12345,
            timestamp_ns: 1000,
            domain,
            domain_len: domain_str.len() as u16,
            family: AF_INET,
            resolved_ip,
            success: 1,
            _padding: [0],
        };

        handle_dns_event(pool.clone(), event, dns_cache.clone(), docker_cache.clone()).await;

        // Verify DB insertion
        let row = sqlx::query("SELECT * FROM dns_events WHERE domain = 'example.com'")
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch DNS event");

        assert_eq!(row.get::<String, _>("domain"), "example.com");
        assert_eq!(row.get::<String, _>("resolved_ip"), "1.2.3.4");
        assert_eq!(row.get::<String, _>("container_name"), "test_container_name");

        // Verify DNS cache update
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let cached_domain = lookup_domain(&dns_cache, &ip, 300).await;
        assert_eq!(cached_domain, Some("example.com".to_string()));
    }
}
