-- Add threat columns to events table
ALTER TABLE events ADD COLUMN is_threat BOOLEAN;
ALTER TABLE events ADD COLUMN threat_source TEXT;

-- Create table for IP threat feeds (Feodo Tracker)
CREATE TABLE threat_ip_feed (
    ip TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create table for URL/Domain threat feeds (URLhaus)
CREATE TABLE threat_domain_feed (
    domain TEXT PRIMARY KEY,
    url TEXT,
    source TEXT NOT NULL,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index for faster lookups
CREATE INDEX idx_threat_ip ON threat_ip_feed(ip);
CREATE INDEX idx_threat_domain ON threat_domain_feed(domain);
