-- Add domain_name column to existing events table
ALTER TABLE events ADD COLUMN domain_name TEXT;

-- Add index for domain name queries
CREATE INDEX idx_events_domain_name ON events(domain_name) WHERE domain_name IS NOT NULL;

-- Create separate dns_events table for debugging and auditing
CREATE TABLE IF NOT EXISTS dns_events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),

    -- DNS query info
    domain TEXT NOT NULL,

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
