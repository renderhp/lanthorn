-- Connection aggregations table
-- Groups connections by: container + process (source) and domain/IP + port (destination)
CREATE TABLE connection_aggregations (
    id INTEGER PRIMARY KEY,

    -- Source: Container + Process
    container_id TEXT,
    container_name TEXT,
    process_name TEXT,

    -- Destination: Domain (with IP fallback) + Port + Protocol
    destination TEXT NOT NULL,  -- domain_name if available, otherwise dst_addr
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,

    -- Aggregation metrics
    connection_count INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Unique index using COALESCE to handle NULLs consistently
-- (SQLite treats NULL values as distinct in UNIQUE constraints, so we use COALESCE)
CREATE UNIQUE INDEX idx_conn_agg_unique ON connection_aggregations(
    COALESCE(container_id, ''),
    COALESCE(process_name, ''),
    destination,
    dst_port,
    protocol
);

-- Indexes for common queries
CREATE INDEX idx_conn_agg_container ON connection_aggregations(container_id);
CREATE INDEX idx_conn_agg_process ON connection_aggregations(process_name);
CREATE INDEX idx_conn_agg_destination ON connection_aggregations(destination);
CREATE INDEX idx_conn_agg_last_seen ON connection_aggregations(last_seen);
