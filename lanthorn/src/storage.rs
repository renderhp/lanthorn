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
    pub is_threat: Option<bool>,
    pub threat_source: Option<String>,
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
        "INSERT INTO events (event_type, protocol, dst_addr, dst_port, pid, cgroup_id, container_id, container_name, image_name, domain_name, process_name, process_cmdline, is_threat, threat_source)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
    .bind(event.is_threat)
    .bind(&event.threat_source)
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

/// Deletes events older than the specified number of days from both events and dns_events tables.
/// Returns the total number of deleted rows.
pub async fn delete_old_events(pool: &SqlitePool, retention_days: u64) -> Result<u64, sqlx::Error> {
    let cutoff = format!("-{} days", retention_days);

    let events_result = sqlx::query("DELETE FROM events WHERE timestamp < datetime('now', ?)")
        .bind(&cutoff)
        .execute(pool)
        .await?;

    let dns_result = sqlx::query("DELETE FROM dns_events WHERE timestamp < datetime('now', ?)")
        .bind(&cutoff)
        .execute(pool)
        .await?;

    let total_deleted = events_result.rows_affected() + dns_result.rows_affected();
    if total_deleted > 0 {
        info!(
            "Retention cleanup: deleted {} events, {} dns_events (older than {} days)",
            events_result.rows_affected(),
            dns_result.rows_affected(),
            retention_days
        );
    }

    Ok(total_deleted)
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
    async fn test_delete_old_events() {
        let pool = setup_db().await;

        // Insert an old event (10 days ago)
        sqlx::query(
            "INSERT INTO events (timestamp, event_type, protocol, dst_addr, dst_port, pid)
             VALUES (datetime('now', '-10 days'), 'tcp_connect', 'tcp', '1.2.3.4', 80, 100)",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Insert a recent event (1 day ago)
        sqlx::query(
            "INSERT INTO events (timestamp, event_type, protocol, dst_addr, dst_port, pid)
             VALUES (datetime('now', '-1 days'), 'tcp_connect', 'tcp', '5.6.7.8', 443, 200)",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Insert an old DNS event (10 days ago)
        sqlx::query(
            "INSERT INTO dns_events (timestamp, domain, pid)
             VALUES (datetime('now', '-10 days'), 'old.example.com', 100)",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Insert a recent DNS event (1 day ago)
        sqlx::query(
            "INSERT INTO dns_events (timestamp, domain, pid)
             VALUES (datetime('now', '-1 days'), 'new.example.com', 200)",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Verify we have 2 events and 2 dns_events before cleanup
        let events_count: i64 = sqlx::query("SELECT COUNT(*) as count FROM events")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("count");
        assert_eq!(events_count, 2);

        let dns_count: i64 = sqlx::query("SELECT COUNT(*) as count FROM dns_events")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("count");
        assert_eq!(dns_count, 2);

        // Run retention cleanup with 3-day retention
        let deleted = delete_old_events(&pool, 3).await.unwrap();
        assert_eq!(deleted, 2); // Should delete 1 event + 1 dns_event

        // Verify only recent events remain
        let events_count: i64 = sqlx::query("SELECT COUNT(*) as count FROM events")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("count");
        assert_eq!(events_count, 1);

        let remaining_event: String = sqlx::query("SELECT dst_addr FROM events")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("dst_addr");
        assert_eq!(remaining_event, "5.6.7.8");

        // Verify only recent DNS event remains
        let dns_count: i64 = sqlx::query("SELECT COUNT(*) as count FROM dns_events")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("count");
        assert_eq!(dns_count, 1);

        let remaining_dns: String = sqlx::query("SELECT domain FROM dns_events")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("domain");
        assert_eq!(remaining_dns, "new.example.com");
    }

    #[tokio::test]
    async fn test_delete_old_events_empty_db() {
        let pool = setup_db().await;

        // Run retention cleanup on empty database
        let deleted = delete_old_events(&pool, 3).await.unwrap();
        assert_eq!(deleted, 0);
    }
}
