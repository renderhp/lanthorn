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
    
    -- Docker info (nullable, filled when container matched)
    container_id TEXT,
    container_name TEXT,
    image_name TEXT
);

-- Indexes for common queries
CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_container_id ON events(container_id);
CREATE INDEX idx_events_cgroup_id ON events(cgroup_id);
CREATE INDEX idx_events_dst ON events(dst_addr, dst_port);