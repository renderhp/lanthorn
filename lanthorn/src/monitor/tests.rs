use super::dns::handle_dns_event;
use super::ebpf::handle_event;
use crate::monitor::ThreatEngine;
use crate::monitor::dns_cache::DnsCache;
use crate::monitor::docker::{DockerCache, MonitoredContainer};
use lanthorn_common::{ConnectEvent, DnsEvent};
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

async fn setup_env() -> (SqlitePool, DnsCache, DockerCache, ThreatEngine) {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let dns_cache = Arc::new(RwLock::new(HashMap::new()));
    let docker_cache = Arc::new(RwLock::new(HashMap::new()));
    let threat_engine = ThreatEngine::new(pool.clone());
    (pool, dns_cache, docker_cache, threat_engine)
}

#[tokio::test]
async fn test_network_events_processing() {
    let (pool, dns_cache, docker_cache, threat_engine) = setup_env().await;

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
        threat_engine.clone(),
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

#[tokio::test]
async fn test_threat_detection() {
    let (pool, dns_cache, docker_cache, threat_engine) = setup_env().await;

    // 1. Seed Threat DB with a known malicious IP and Domain
    let malicious_ip = "192.168.1.66";
    let malicious_domain = "evil.com";
    let malicious_domain_ip = "10.0.0.1";

    sqlx::query("INSERT INTO threat_ip_feed (ip, source) VALUES (?, ?)")
        .bind(malicious_ip)
        .bind("Feodo Tracker")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("INSERT INTO threat_domain_feed (domain, source) VALUES (?, ?)")
        .bind(malicious_domain)
        .bind("URLhaus")
        .execute(&pool)
        .await
        .unwrap();

    // Reload cache to pick up the manual inserts
    threat_engine.load_cache().await.unwrap();

    // 2. Simulate connection to Malicious IP
    let mut ip_bytes = [0u8; 16];
    // 192.168.1.66
    ip_bytes[0] = 192;
    ip_bytes[1] = 168;
    ip_bytes[2] = 1;
    ip_bytes[3] = 66;

    let event_ip = ConnectEvent {
        pid: 123,
        cgroup_id: 1,
        timestamp_ns: 1000,
        ip: ip_bytes,
        port: 80,
        family: 2,
    };

    handle_event(
        pool.clone(),
        event_ip,
        docker_cache.clone(),
        dns_cache.clone(),
        threat_engine.clone(),
    )
    .await;

    // Verify IP threat detected
    let row = sqlx::query("SELECT is_threat, threat_source FROM events WHERE dst_addr = ?")
        .bind(malicious_ip)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(row.get::<bool, _>("is_threat"), true);
    assert_eq!(row.get::<String, _>("threat_source"), "Feodo Tracker");

    // 3. Simulate connection to Malicious Domain
    // First, populate DNS cache
    let mut ip_domain_bytes = [0u8; 16];
    ip_domain_bytes[0] = 10;
    ip_domain_bytes[3] = 1;

    // We need to put it in the cache manually since we are skipping handle_dns_event for brevity
    // or we can simulate it properly. Let's simulate properly.
    let mut domain_bytes = [0u8; 128];
    domain_bytes[..malicious_domain.len()].copy_from_slice(malicious_domain.as_bytes());

    let dns_event = DnsEvent {
        pid: 123,
        cgroup_id: 1,
        timestamp_ns: 2000,
        domain: domain_bytes,
        domain_len: malicious_domain.len() as u16,
        family: 2,
        resolved_ip: ip_domain_bytes,
        success: 1,
        _padding: [0],
    };

    handle_dns_event(
        pool.clone(),
        dns_event,
        dns_cache.clone(),
        docker_cache.clone(),
    )
    .await;

    // Now connect to that IP
    let event_domain = ConnectEvent {
        pid: 123,
        cgroup_id: 1,
        timestamp_ns: 3000,
        ip: ip_domain_bytes,
        port: 443,
        family: 2,
    };

    handle_event(
        pool.clone(),
        event_domain,
        docker_cache.clone(),
        dns_cache.clone(),
        threat_engine.clone(),
    )
    .await;

    // Verify Domain threat detected
    let row = sqlx::query("SELECT is_threat, threat_source FROM events WHERE dst_addr = ?")
        .bind(malicious_domain_ip)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(row.get::<bool, _>("is_threat"), true);
    assert_eq!(row.get::<String, _>("threat_source"), "URLhaus");
}
