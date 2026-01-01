-- Add resolved_ip column to dns_events table for storing the actual IP address
-- that a domain was resolved to, captured via uretprobe on getaddrinfo.
ALTER TABLE dns_events ADD COLUMN resolved_ip TEXT;
