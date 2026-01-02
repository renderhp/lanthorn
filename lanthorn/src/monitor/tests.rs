use super::dns::handle_dns_event;
use super::ebpf::handle_event;
use crate::monitor::dns_cache::DnsCache;
use crate::monitor::docker::{DockerCache, MonitoredContainer};
use lanthorn_common::{ConnectEvent, DnsEvent};
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

async fn setup_env() -> (SqlitePool, DnsCache, DockerCache) {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let dns_cache = Arc::new(RwLock::new(HashMap::new()));
    let docker_cache = Arc::new(RwLock::new(HashMap::new()));
    (pool, dns_cache, docker_cache)
}

#[tokio::test]
async fn test_network_events_processing() {
    let (pool, dns_cache, docker_cache) = setup_env().await;

    // 1. Pre-fill Docker cache with a known container
    let container_id = "container_123";
    let container_pid = 100;
    let cgroup_id = 12345;
    let container_name = "test_app";

    let container = MonitoredContainer {
        id: container_id.to_string(),
        names: Some(vec![container_name.to_string()]),
        image: Some("test_image:latest".to_string()),
        pid: container_pid,
        cgroup_id,
    };
    docker_cache.write().await.insert(cgroup_id, container);

    // 2. Simulate a DNS Event (e.g., app resolving "api.example.com")
    let domain_str = "api.example.com";
    let ip_str = "1.2.3.4";

    // Construct DnsEvent
    let mut domain = [0u8; 128];
    domain[..domain_str.len()].copy_from_slice(domain_str.as_bytes());

    let mut resolved_ip = [0u8; 16];
    // manually parse 1.2.3.4
    resolved_ip[0] = 1;
    resolved_ip[1] = 2;
    resolved_ip[2] = 3;
    resolved_ip[3] = 4;

    let dns_event = DnsEvent {
        pid: container_pid as u32,
        cgroup_id,
        timestamp_ns: 1000,
        domain,
        domain_len: domain_str.len() as u16,
        family: 2, // AF_INET
        resolved_ip,
        success: 1,
        _padding: [0],
    };

    // Process DNS event
    handle_dns_event(
        pool.clone(),
        dns_event,
        dns_cache.clone(),
        docker_cache.clone(),
    )
    .await;

    // 3. Verify DNS event in DB
    let dns_row = sqlx::query("SELECT * FROM dns_events WHERE domain = ?")
        .bind(domain_str)
        .fetch_one(&pool)
        .await
        .expect("DNS event should be in DB");

    assert_eq!(dns_row.get::<String, _>("resolved_ip"), ip_str);
    assert_eq!(dns_row.get::<String, _>("container_name"), container_name);

    // 4. Simulate a TCP Connect Event to the resolved IP
    let connect_event = ConnectEvent {
        pid: container_pid as u32,
        cgroup_id,
        timestamp_ns: 2000,
        ip: resolved_ip,
        port: 443,
        family: 2,
    };

    // Process Connect event
    handle_event(
        pool.clone(),
        connect_event,
        docker_cache.clone(),
        dns_cache.clone(),
    )
    .await;

    // 5. Verify Connect event in DB and check enrichment
    let event_row = sqlx::query("SELECT * FROM events WHERE dst_addr = ? AND dst_port = ?")
        .bind(ip_str)
        .bind(443)
        .fetch_one(&pool)
        .await
        .expect("Connect event should be in DB");

    assert_eq!(event_row.get::<String, _>("container_name"), container_name);
    // Crucially, verify that the domain name was enriched from the DNS cache
    assert_eq!(event_row.get::<String, _>("domain_name"), domain_str);
}
