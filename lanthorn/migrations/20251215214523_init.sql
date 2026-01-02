-- Events table
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    
    -- Connection info
    event_type TEXT NOT NULL,  -- 'tcp_connect', 'tcp_accept', 'udp_send', 'udp_recv', etc.
    protocol TEXT NOT NULL,    -- 'tcp', 'udp'
    
    -- Destination
    dst_addr TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    
    -- Process info from eBPF
    pid INTEGER NOT NULL,
    cgroup_id INTEGER,
    process_name TEXT,
    process_cmdline TEXT,
    
    -- Docker info (nullable, filled when container matched)
    container_id TEXT,
    container_name TEXT,
    image_name TEXT,

    -- DNS info
    domain_name TEXT,

    -- Threat info
    is_threat BOOLEAN,
    threat_source TEXT
);

-- Indexes for common queries on events
CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_container_id ON events(container_id);
CREATE INDEX idx_events_cgroup_id ON events(cgroup_id);
CREATE INDEX idx_events_dst ON events(dst_addr, dst_port);
CREATE INDEX idx_events_domain_name ON events(domain_name) WHERE domain_name IS NOT NULL;


-- DNS events table
CREATE TABLE IF NOT EXISTS dns_events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),

    -- DNS query info
    domain TEXT NOT NULL,
    resolved_ip TEXT,

    -- Process info from eBPF
    pid INTEGER NOT NULL,
    cgroup_id INTEGER,

    -- Docker info (nullable, filled when container matched)
    container_id TEXT,
    container_name TEXT,
    image_name TEXT
);

-- Indexes for common queries on dns_events
CREATE INDEX idx_dns_events_timestamp ON dns_events(timestamp);
CREATE INDEX idx_dns_events_domain ON dns_events(domain);
CREATE INDEX idx_dns_events_container_id ON dns_events(container_id);
CREATE INDEX idx_dns_events_pid ON dns_events(pid);


-- Threat tables
CREATE TABLE threat_ip_feed (
    ip TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE threat_domain_feed (
    domain TEXT PRIMARY KEY,
    url TEXT,
    source TEXT NOT NULL,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for threat feeds
CREATE INDEX idx_threat_ip ON threat_ip_feed(ip);
CREATE INDEX idx_threat_domain ON threat_domain_feed(domain);
