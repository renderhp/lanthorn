use log::info;
use sqlx::SqlitePool;

pub async fn init(path: &str) -> Result<SqlitePool, sqlx::Error> {
    info!("Initialising DB at path: {}", path);
    let url = format!("sqlite:{}?mode=rwc", path);
    let pool = SqlitePool::connect(&url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

pub async fn insert_event(
    pool: &SqlitePool,
    event_type: &str,
    protocol: &str,
    dst_addr: &str,
    dst_port: u16,
    pid: u32,
    cgroup_id: Option<u64>,
    container_id: Option<String>,
    container_name: Option<String>,
    container_image: Option<String>,
    domain_name: Option<String>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO events (event_type, protocol, dst_addr, dst_port, pid, cgroup_id, container_id, container_name, image_name, domain_name)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(event_type)
    .bind(protocol)
    .bind(dst_addr)
    .bind(dst_port as i64)
    .bind(pid as i64)
    .bind(cgroup_id.map(|v| v as i64))
    .bind(container_id)
    .bind(container_name)
    .bind(container_image)
    .bind(domain_name)
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
         VALUES (?, ?, ?, ?, ?, ?)"
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
