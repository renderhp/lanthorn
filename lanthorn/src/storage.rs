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

#[allow(clippy::too_many_arguments)]
pub async fn insert_dns_event(
    pool: &SqlitePool,
    domain: &str,
    resolved_ip: Option<&str>,
    pid: u32,
    cgroup_id: Option<u64>,
    container_id: Option<String>,
    container_name: Option<String>,
    container_image: Option<String>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO dns_events (domain, resolved_ip, pid, cgroup_id, container_id, container_name, image_name)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(domain)
    .bind(resolved_ip)
    .bind(pid as i64)
    .bind(cgroup_id.map(|v| v as i64))
    .bind(container_id)
    .bind(container_name)
    .bind(container_image)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    async fn setup_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn test_insert_event() {
        let pool = setup_db().await;

        let event = EventData {
            event_type: "tcp_connect".to_string(),
            protocol: "tcp".to_string(),
            dst_addr: "127.0.0.1".to_string(),
            dst_port: 80,
            pid: 1234,
            cgroup_id: Some(100),
            container_id: Some("container123".to_string()),
            container_name: Some("my_container".to_string()),
            container_image: Some("ubuntu:latest".to_string()),
            domain_name: Some("example.com".to_string()),
            process_name: Some("curl".to_string()),
            process_cmdline: Some("curl example.com".to_string()),
        };

        insert_event(&pool, &event).await.expect("Failed to insert event");

        let row = sqlx::query("SELECT * FROM events WHERE pid = 1234")
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch event");

        assert_eq!(row.get::<String, _>("event_type"), "tcp_connect");
        assert_eq!(row.get::<String, _>("dst_addr"), "127.0.0.1");
        assert_eq!(row.get::<i64, _>("dst_port"), 80);
        assert_eq!(row.get::<String, _>("process_name"), "curl");
    }

    #[tokio::test]
    async fn test_insert_dns_event() {
        let pool = setup_db().await;

        insert_dns_event(
            &pool,
            "example.com",
            Some("93.184.216.34"),
            1234,
            Some(100),
            Some("container123".to_string()),
            Some("my_container".to_string()),
            Some("ubuntu:latest".to_string()),
        ).await.expect("Failed to insert DNS event");

        let row = sqlx::query("SELECT * FROM dns_events WHERE domain = 'example.com'")
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch DNS event");

        assert_eq!(row.get::<String, _>("domain"), "example.com");
        assert_eq!(row.get::<String, _>("resolved_ip"), "93.184.216.34");
        assert_eq!(row.get::<i64, _>("pid"), 1234);
    }
}
