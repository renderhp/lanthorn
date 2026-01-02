use aya::{Ebpf, maps::RingBuf, programs::KProbe};
use aya_log::EbpfLogger;
use lanthorn_common::ConnectEvent;
use log::{info, warn};
use sqlx::SqlitePool;
use tokio::io::unix::AsyncFd;

use crate::{
    monitor::{
        DockerCache,
        dns_cache::{DnsCache, lookup_domain},
    },
    storage,
    utils::{get_process_cmdline, get_process_name, ip_to_string},
};

const DNS_CACHE_TTL_SECS: u64 = 300; // 5 minutes

pub async fn run_tcp_monitor(
    pool: SqlitePool,
    docker_cache: DockerCache,
    dns_cache: DnsCache,
) -> Result<(), anyhow::Error> {
    info!("Starting TCP connection monitor...");

    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lanthorn"
    )))?;

    match EbpfLogger::init(&mut bpf) {
        Err(e) => {
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

    let ring_buf = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    let mut ring_buf_poll = AsyncFd::new(ring_buf).unwrap();
    info!("Waiting for events...");

    loop {
        let mut guard = ring_buf_poll.readable_mut().await.unwrap();

        while let Some(item) = guard.get_inner_mut().next() {
            let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const ConnectEvent) };
            handle_event(pool.clone(), event, docker_cache.clone(), dns_cache.clone()).await;
        }

        guard.clear_ready();
    }
}

pub(crate) async fn handle_event(
    pool: SqlitePool,
    event: ConnectEvent,
    docker_cache: DockerCache,
    dns_cache: DnsCache,
) {
    info!(
        "Connection: PID={}, Port={}, Family={}, CGroup={}",
        event.pid, event.port, event.family, event.cgroup_id
    );

    let ip_string = ip_to_string(event.family, event.ip);
    let Some(ip) = ip_string else {
        warn!("Could not parse IP, skipping event");
        return;
    };

    // Parse IP address for DNS lookup
    let ip_addr: Option<std::net::IpAddr> = ip.parse().ok();

    // Look up domain name directly in DNS cache (populated by uretprobe)
    let domain_name = if let Some(ref addr) = ip_addr {
        lookup_domain(&dns_cache, addr, DNS_CACHE_TTL_SECS).await
    } else {
        None
    };

    if let Some(ref domain) = domain_name {
        info!("  {} ({})", ip, domain);
    } else {
        info!("  {}", ip);
    }

    let docker_info = docker_cache.read().await.get(&event.cgroup_id).cloned();
    if let Some(info) = &docker_info {
        info!(
            "  Container Names: {:?}, Image: {:?}, PID: {}, ID: {}",
            info.names, info.image, info.pid, info.id
        );
    }

    let container_name = docker_info
        .as_ref()
        .and_then(|d| d.names.clone())
        .and_then(|v| v.first().cloned());
    let container_id = docker_info.as_ref().map(|d| d.id.clone());
    let image_name = docker_info.as_ref().and_then(|d| d.image.clone());

    // Enrich with process info from /proc
    let process_name = get_process_name(event.pid).ok();
    let process_cmdline = get_process_cmdline(event.pid).ok();

    if let Some(ref name) = process_name {
        info!("  Process: {}", name);
    }

    let event_data = storage::EventData {
        event_type: "tcp_connect".to_string(),
        protocol: "tcp".to_string(),
        dst_addr: ip,
        dst_port: event.port,
        pid: event.pid,
        cgroup_id: Some(event.cgroup_id),
        container_id,
        container_name,
        container_image: image_name,
        domain_name,
        process_name,
        process_cmdline,
    };

    let _ = storage::insert_event(&pool, &event_data).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::RwLock;
    use sqlx::Row;
    use crate::monitor::dns_cache::{DnsCacheEntry, insert_mapping};
    use crate::monitor::docker::MonitoredContainer;

    async fn setup_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn test_handle_connect_event() {
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

        // Pre-fill DNS cache
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let entry = DnsCacheEntry {
            domain: "example.com".to_string(),
            timestamp_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        };
        insert_mapping(&dns_cache, ip, entry).await;

        // Construct ConnectEvent
        // IPv4 1.2.3.4 mapped to [u8; 16]
        let mut ip_bytes = [0u8; 16];
        ip_bytes[0] = 1;
        ip_bytes[1] = 2;
        ip_bytes[2] = 3;
        ip_bytes[3] = 4;

        let event = ConnectEvent {
            pid: 100,
            cgroup_id: 12345,
            timestamp_ns: 1000,
            ip: ip_bytes,
            port: 80,
            family: 2, // AF_INET
        };

        handle_event(pool.clone(), event, docker_cache.clone(), dns_cache.clone()).await;

        // Verify DB insertion
        let row = sqlx::query("SELECT * FROM events WHERE pid = 100")
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch event");

        assert_eq!(row.get::<String, _>("dst_addr"), "1.2.3.4");
        assert_eq!(row.get::<i64, _>("dst_port"), 80);
        assert_eq!(row.get::<String, _>("container_name"), "test_container_name");
        assert_eq!(row.get::<String, _>("domain_name"), "example.com");
    }
}
