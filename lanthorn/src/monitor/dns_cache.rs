use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::sync::RwLock;

pub type DnsCache = Arc<RwLock<HashMap<IpAddr, DnsCacheEntry>>>;

#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub domain: String,
    pub timestamp_ns: u64, // When this was resolved (from eBPF event)
}

impl DnsCacheEntry {
    /// Check if cache entry is expired (default TTL: 300 seconds)
    pub fn is_expired(&self, ttl_secs: u64) -> bool {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let age_ns = now_ns.saturating_sub(self.timestamp_ns);
        let age_secs = age_ns / 1_000_000_000;

        age_secs > ttl_secs
    }
}

/// Look up domain name for an IP address
pub async fn lookup_domain(cache: &DnsCache, ip: &IpAddr, ttl_secs: u64) -> Option<String> {
    let cache_lock = cache.read().await;

    if let Some(entry) = cache_lock.get(ip)
        && !entry.is_expired(ttl_secs)
    {
        return Some(entry.domain.clone());
    }

    None
}

/// Insert domain -> IP mapping into cache
pub async fn insert_mapping(cache: &DnsCache, ip: IpAddr, entry: DnsCacheEntry) {
    let mut cache_lock = cache.write().await;
    cache_lock.insert(ip, entry);
}

/// Evict expired entries (run periodically)
pub async fn evict_expired(cache: &DnsCache, ttl_secs: u64) -> usize {
    let mut cache_lock = cache.write().await;
    let initial_len = cache_lock.len();

    cache_lock.retain(|_ip, entry| !entry.is_expired(ttl_secs));

    initial_len - cache_lock.len()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use super::*;

    #[tokio::test]
    async fn test_cache_insert_and_lookup() {
        let cache: DnsCache = Arc::new(RwLock::new(HashMap::new()));
        let ip: IpAddr = "93.184.216.34".parse().unwrap();

        let entry = DnsCacheEntry {
            domain: "example.com".to_string(),
            timestamp_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        };

        insert_mapping(&cache, ip, entry).await;

        let result = lookup_domain(&cache, &ip, 300).await;
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache: DnsCache = Arc::new(RwLock::new(HashMap::new()));
        let ip: IpAddr = "93.184.216.34".parse().unwrap();

        // Create entry with very old timestamp
        let entry = DnsCacheEntry {
            domain: "example.com".to_string(),
            timestamp_ns: 1, // Very old
        };

        insert_mapping(&cache, ip, entry).await;

        // Should be expired with 1 second TTL
        let result = lookup_domain(&cache, &ip, 1).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_evict_expired() {
        let cache: DnsCache = Arc::new(RwLock::new(HashMap::new()));

        // Insert fresh entry
        let ip1: IpAddr = "93.184.216.34".parse().unwrap();
        let entry1 = DnsCacheEntry {
            domain: "example.com".to_string(),
            timestamp_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        };
        insert_mapping(&cache, ip1, entry1).await;

        // Insert expired entry
        let ip2: IpAddr = "192.0.2.1".parse().unwrap();
        let entry2 = DnsCacheEntry {
            domain: "old.example.com".to_string(),
            timestamp_ns: 1,
        };
        insert_mapping(&cache, ip2, entry2).await;

        // Evict with short TTL
        let evicted = evict_expired(&cache, 1).await;
        assert_eq!(evicted, 1);

        // Fresh entry should still be there
        let result1 = lookup_domain(&cache, &ip1, 300).await;
        assert_eq!(result1, Some("example.com".to_string()));

        // Old entry should be gone
        let result2 = lookup_domain(&cache, &ip2, 300).await;
        assert_eq!(result2, None);
    }
}
