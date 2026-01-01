use log::info;
use sqlx::SqlitePool;

pub struct EventData {
    pub event_type: String,
    pub protocol: String,
    pub dst_addr: String,
    pub dst_port: u16,
    pub pid: u32,
    pub cgroup_id: Option<u64>,
    pub container_id: Option<String>,
    pub container_name: Option<String>,
    pub container_image: Option<String>,
    pub domain_name: Option<String>,
    pub process_name: Option<String>,
    pub process_cmdline: Option<String>,
}

pub async fn init(path: &str) -> Result<SqlitePool, sqlx::Error> {
    info!("Initialising DB at path: {}", path);
    let url = format!("sqlite:{}?mode=rwc", path);
    let pool = SqlitePool::connect(&url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

pub async fn insert_event(pool: &SqlitePool, event: &EventData) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO events (event_type, protocol, dst_addr, dst_port, pid, cgroup_id, container_id, container_name, image_name, domain_name, process_name, process_cmdline)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&event.event_type)
    .bind(&event.protocol)
    .bind(&event.dst_addr)
    .bind(event.dst_port as i64)
    .bind(event.pid as i64)
    .bind(event.cgroup_id.map(|v| v as i64))
    .bind(&event.container_id)
    .bind(&event.container_name)
    .bind(&event.container_image)
    .bind(&event.domain_name)
    .bind(&event.process_name)
    .bind(&event.process_cmdline)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn insert_dns_event(
    pool: &SqlitePool,
    domain: &str,
    pid: u32,
    cgroup_id: Option<u64>,
    container_id: Option<String>,
    container_name: Option<String>,
    container_image: Option<String>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO dns_events (domain, pid, cgroup_id, container_id, container_name, image_name)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(domain)
    .bind(pid as i64)
    .bind(cgroup_id.map(|v| v as i64))
    .bind(container_id)
    .bind(container_name)
    .bind(container_image)
    .execute(pool)
    .await?;

    Ok(())
}
