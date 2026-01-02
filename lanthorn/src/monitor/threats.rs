use log::{error, info};
use reqwest::Client;
use serde::Deserialize;
use sqlx::{Row, SqlitePool};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

const FEODO_TRACKER_URL: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";
const URLHAUS_URL: &str = "https://urlhaus.abuse.ch/downloads/json/";

#[derive(Clone)]
pub struct ThreatEngine {
    pool: SqlitePool,
    ip_blocklist: Arc<RwLock<HashSet<String>>>,
    domain_blocklist: Arc<RwLock<HashMap<String, String>>>, // domain -> url/info
    client: Client,
}

#[derive(Deserialize)]
struct FeodoEntry {
    ip_address: String,
    // malware: String, // could use this for extra info
}

#[derive(Deserialize)]
struct UrlHausEntry {
    // id: String,
    // url: String,
    // url_status: String,
    // threat: String,
    // tags: Option<Vec<String>>,
    // urlhaus_link: String,
    // reporter: String,
    // date_added: String,
    host: String,
}

// URLhaus JSON format is {"query_status": "ok", "urls": [...]}
#[derive(Deserialize)]
struct UrlHausResponse {
    query_status: String,
    urls: Vec<UrlHausEntry>,
}

impl ThreatEngine {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            ip_blocklist: Arc::new(RwLock::new(HashSet::new())),
            domain_blocklist: Arc::new(RwLock::new(HashMap::new())),
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    pub async fn load_cache(&self) -> Result<(), sqlx::Error> {
        info!("Loading threat feeds from database...");

        // Load IPs
        let ips = sqlx::query("SELECT ip FROM threat_ip_feed")
            .fetch_all(&self.pool)
            .await?;

        {
            let mut cache = self.ip_blocklist.write().unwrap();
            cache.clear();
            for record in ips {
                cache.insert(record.get("ip"));
            }
        }

        // Load Domains
        let domains = sqlx::query("SELECT domain, url FROM threat_domain_feed")
            .fetch_all(&self.pool)
            .await?;

        {
            let mut cache = self.domain_blocklist.write().unwrap();
            cache.clear();
            for record in domains {
                cache.insert(
                    record.get("domain"),
                    record.get::<Option<String>, _>("url").unwrap_or_default(),
                );
            }
        }

        info!(
            "Threat cache loaded: {} IPs, {} domains",
            self.ip_blocklist.read().unwrap().len(),
            self.domain_blocklist.read().unwrap().len()
        );

        Ok(())
    }

    pub async fn fetch_feeds(&self) -> Result<(), anyhow::Error> {
        info!("Fetching threat feeds...");

        // Fetch Feodo Tracker
        match self.fetch_feodo().await {
            Ok(count) => info!("Fetched {} IPs from Feodo Tracker", count),
            Err(e) => error!("Failed to fetch Feodo Tracker: {}", e),
        }

        // Fetch URLhaus
        match self.fetch_urlhaus().await {
            Ok(count) => info!("Fetched {} domains from URLhaus", count),
            Err(e) => error!("Failed to fetch URLhaus: {}", e),
        }

        // Reload cache after update
        self.load_cache().await?;

        Ok(())
    }

    async fn fetch_feodo(&self) -> Result<usize, anyhow::Error> {
        let resp = self
            .client
            .get(FEODO_TRACKER_URL)
            .send()
            .await?
            .error_for_status()?;
        let entries: Vec<FeodoEntry> = resp.json().await?;

        let mut tx = self.pool.begin().await?;

        // Clear old data? Or upset? Roadmap says "Fetch threat feeds on startup".
        // Usually full replacement is safer for blocklists to remove stale entries.
        sqlx::query("DELETE FROM threat_ip_feed WHERE source = 'Feodo Tracker'")
            .execute(&mut *tx)
            .await?;

        for entry in &entries {
            sqlx::query("INSERT OR IGNORE INTO threat_ip_feed (ip, source) VALUES (?, ?)")
                .bind(&entry.ip_address)
                .bind("Feodo Tracker")
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(entries.len())
    }

    async fn fetch_urlhaus(&self) -> Result<usize, anyhow::Error> {
        // URLhaus is huge. We might want to stream it if possible, but for now just load JSON.
        // If it's too big, we might need a different approach.
        // For MVP, let's try standard JSON.
        let resp = self
            .client
            .get(URLHAUS_URL)
            .send()
            .await?
            .error_for_status()?;
        let data: UrlHausResponse = resp.json().await?;

        if data.query_status != "ok" {
            return Err(anyhow::anyhow!(
                "URLhaus query status not ok: {}",
                data.query_status
            ));
        }

        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM threat_domain_feed WHERE source = 'URLhaus'")
            .execute(&mut *tx)
            .await?;

        // Use a set to dedup domains from URLs
        let mut domains = HashSet::new();
        for entry in data.urls {
            // entry.host could be a domain or IP.
            domains.insert(entry.host);
        }

        for domain in &domains {
            sqlx::query("INSERT OR IGNORE INTO threat_domain_feed (domain, source) VALUES (?, ?)")
                .bind(domain)
                .bind("URLhaus")
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(domains.len())
    }

    pub fn check_threat(&self, ip: &str, domain: Option<&str>) -> Option<(bool, String)> {
        // Check IP
        if self.ip_blocklist.read().unwrap().contains(ip) {
            return Some((true, "Feodo Tracker".to_string()));
        }

        // Check Domain
        if let Some(d) = domain
            && self.domain_blocklist.read().unwrap().contains_key(d)
        {
            return Some((true, "URLhaus".to_string()));
        }

        None
    }
}
