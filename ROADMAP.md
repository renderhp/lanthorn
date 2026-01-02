# Lanthorn Roadmap

This document outlines the planned development roadmap for Lanthorn, a network connection monitoring tool for homelab security.

## Vision

Lanthorn helps homelab users answer: "What is my infrastructure talking to, and should I be worried?"

Core principles:
- **Single binary** - No complex deployment, just run it
- **Container-aware** - First-class Docker integration
- **Security-focused** - Flag suspicious connections, integrate threat intelligence
- **Low friction** - Embedded web UI, sensible defaults

---

## v0.1 - Foundation + Web Dashboard

The first release focuses on providing visibility into network connections with a usable web interface.

### Phase 1: Data Enrichment

Enhance captured data with actionable context.

- [x] Capture process name from `/proc/{pid}/comm`
- [x] Capture process command line from `/proc/{pid}/cmdline`
- [x] Fetch threat feeds on startup (abuse.ch URLhaus + Feodo Tracker)
- [x] Match connections against threat feeds
- [x] Update database schema:
  - [x] `process_name` - executable name
  - [x] `process_cmdline` - full command line
  - [x] `is_threat` - boolean flag
  - [x] `threat_source` - which feed matched

### Phase 2: Data Lifecycle

Manage storage with retention and aggregation.

- [x] Aggregated connections table schema:
  - destination (IP/domain)
  - container
  - port
  - connection_count
  - first_seen
  - last_seen
- [x] Inline aggregation (update aggregates on each event)
- [x] Configurable retention period (default: 3 days for full logs)
- [x] Cleanup job for expired detailed logs

### Phase 3: API Layer

REST API for the web dashboard. Web server should run without sudo privileges by forking the process and dropping privs.

- [ ] Embed Axum web server
- [ ] Configurable port (default: 7777 or similar)
- [ ] API endpoints:
  - `GET /api/containers` - list containers with connection stats
  - `GET /api/containers/:id` - container details
  - `GET /api/containers/:id/connections` - connections for a container
  - `GET /api/connections` - all connections (paginated, filterable)
  - `GET /api/graph` - network graph data structure
  - `GET /api/stats` - dashboard summary statistics
  - `GET /api/threats` - connections flagged as threats
  - `GET /api/dns` - DNS query log

### Phase 4: Web Dashboard

React-based embedded UI.

**Tech stack:**
- Vite + React 18
- TanStack Query (data fetching)
- TanStack Router (routing)
- Tailwind CSS (styling)
- Recharts or Chart.js (statistics)
- react-force-graph or @antv/g6 (network visualization)

**Views:**

- [ ] **Container list** (primary view)
  - All containers with connection counts
  - Threat indicators
  - Quick stats (unique destinations, countries)

- [ ] **Container detail**
  - Destinations this container connects to
  - Ports used
  - Countries reached
  - Threat matches
  - Connection timeline

- [ ] **Network graph**
  - Containers as nodes
  - External destinations as nodes (grouped by TLD or country - TBD)
  - Edges showing connections
  - Visual threat highlighting

- [ ] **Dashboard overview**
  - Connections per hour/day
  - Unique destinations
  - Threat match count
  - Top talkers (containers with most connections)

- [ ] **Embed in binary**
  - Build React app to static files
  - Use rust-embed to include in binary
  - Serve via Axum

### Phase 5: Polish & Release

- [ ] Configuration file support (TOML)
  - Retention period
  - Web UI port
  - Threat feed URLs
  - Enable/disable features
- [ ] CLI flags for common options
- [ ] User documentation
- [ ] Release binaries (x86_64, aarch64)

---

## Post-v0.1 Roadmap

Features planned for future releases, roughly ordered by priority.

### GeoIP Enrichment

- Integrate MaxMind GeoLite2 for IP-to-country lookup
- Add `country` column to database schema (2-letter country code)
- Display country information in web dashboard

### Performance Optimization

- Optimize event logging throughput
- Improve aggregation update performance
- Batch database writes where beneficial

### Container-to-Container Traffic

- Hook `tcp_accept` or `inet_csk_accept` for inbound connections
- Correlate inbound/outbound to show container-to-container flows
- Visualize internal traffic patterns in network graph

### Alerting & Notifications

- Webhook support (generic HTTP POST)
- ntfy.sh integration
- Desktop notifications
- Email (optional, requires SMTP config)
- Alert conditions:
  - Threat feed match
  - New destination never seen before
  - Connection to unexpected country
  - Custom rules

### User-Defined Rules

- "Alert if container X connects to anything other than Y"
- "Ignore connections to local network"
- "Flag any connection on port 22"
- Rule engine with simple DSL or YAML config

### Historical Analysis

- Trend graphs over time
- "What changed this week?"
- Baseline detection (normal vs. anomalous)
- Comparison views (today vs. last week)

### Process Tracking Enhancements

- Parent process chain (who spawned this process?)
- Process start time
- User/UID that owns the process
- Correlate with container entrypoint

### Protocol Expansion

- UDP connection tracking
- QUIC/HTTP3 awareness
- TLS certificate inspection (SNI extraction)

### Multi-Host Support

- Central aggregation server
- Lightweight agent mode
- Cross-host network graph
- Fleet-wide threat detection

### Baseline Learning

- Learn "normal" behavior over time
- Alert on deviations
- Per-container baselines
- Time-of-day awareness (weekday vs. weekend patterns)

---

## Threat Feed Sources

Initial integration targets:

| Source | URL | Content |
|--------|-----|---------|
| abuse.ch URLhaus | https://urlhaus.abuse.ch/downloads/json/ | Malicious URLs/domains |
| abuse.ch Feodo Tracker | https://feodotracker.abuse.ch/downloads/ipblocklist.json | Botnet C2 IPs |

Future additions:
- Spamhaus DROP (IP ranges)
- Emerging Threats (compromised IPs)
- User-provided custom blocklists

---

## Non-Goals (for now)

Things explicitly out of scope to keep focus:

- Windows/macOS support (Linux + eBPF only)
- Network packet inspection (we track connections, not content)
- Blocking/firewall functionality (monitoring only)
- Cloud/SaaS deployment
- Mobile app

---

## Contributing

This roadmap is a living document. If you're interested in contributing to any of these features, please open an issue to discuss before starting work.
