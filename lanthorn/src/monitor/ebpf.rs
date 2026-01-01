use aya::{Ebpf, maps::RingBuf, programs::KProbe};
use aya_log::EbpfLogger;
use lanthorn_common::ConnectEvent;
use log::{info, warn};
use sqlx::SqlitePool;
use tokio::io::unix::AsyncFd;

use crate::{
    monitor::{
        DockerCache,
        dns_cache::{DnsCache, PendingDnsCache, resolve_domain_for_connection},
    },
    storage,
    utils::{get_process_cmdline, get_process_name, ip_to_string},
};

pub async fn run_tcp_monitor(
    pool: SqlitePool,
    docker_cache: DockerCache,
    dns_cache: DnsCache,
    pending_dns_cache: PendingDnsCache,
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
            handle_event(
                pool.clone(),
                event,
                docker_cache.clone(),
                dns_cache.clone(),
                pending_dns_cache.clone(),
            )
            .await;
        }

        guard.clear_ready();
    }
}

async fn handle_event(
    pool: SqlitePool,
    event: ConnectEvent,
    docker_cache: DockerCache,
    dns_cache: DnsCache,
    pending_dns_cache: PendingDnsCache,
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

    // Look up domain name in DNS cache using the timestamp from eBPF event
    let domain_name = if let Some(addr) = ip_addr {
        resolve_domain_for_connection(
            &pending_dns_cache,
            &dns_cache,
            event.pid,
            &addr,
            event.timestamp_ns,
            300, // 5 minute TTL
        )
        .await
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

    let _ = storage::insert_event(
        &pool,
        "tcp_connect",
        "tcp",
        &ip,
        event.port,
        event.pid,
        Some(event.cgroup_id),
        container_id,
        container_name,
        image_name,
        domain_name,
        process_name,
        process_cmdline,
    )
    .await;
}
