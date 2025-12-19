# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Lanthorn is a network connection monitoring tool that uses eBPF (Extended Berkeley Packet Filter) to track TCP connections at the kernel level. It also tracks DNS resolutions to enrich connection events with domain names. The tool correlates network activity with Docker containers and stores events in a SQLite database.

## Project Structure

This is a Rust workspace with three crates:

- **lanthorn** - Main userspace application that loads eBPF programs, monitors Docker containers, tracks DNS resolutions, and stores events
- **lanthorn-ebpf** - eBPF kernel-space program that hooks into `tcp_connect` and `getaddrinfo` to capture connection and DNS events
- **lanthorn-common** - Shared data structures (`ConnectEvent` and `DnsEvent`) used by both userspace and kernel-space code

### Key Architecture Components

1. **TCP Monitoring** (`lanthorn/src/monitor/ebpf.rs`)
   - Loads the eBPF program from `lanthorn-ebpf` at runtime
   - Attaches a kprobe to `tcp_connect` kernel function
   - Reads connection events from a ring buffer shared with kernel space
   - Enriches events with domain names from DNS cache
   - Correlates events with Docker containers using cgroup IDs

2. **DNS Monitoring** (`lanthorn/src/monitor/dns.rs`)
   - Attaches a uprobe to `getaddrinfo` in libc to capture DNS queries
   - Reads DNS events from a separate DNS_EVENTS ring buffer
   - Maintains two-level caching:
     - `PendingDnsCache`: Recent DNS queries by PID (30-second window)
     - `DnsCache`: IP→domain mappings (5-minute TTL)
   - Correlates DNS queries with TCP connections using PID and timestamps
   - Stores DNS events in separate `dns_events` table for auditing

3. **Docker Monitoring** (`lanthorn/src/monitor/docker.rs`)
   - Maintains a cache mapping cgroup IDs to container metadata
   - Uses the Bollard library to interact with Docker API
   - Resolves cgroup IDs by reading `/proc/{pid}/cgroup` and getting inode numbers from `/sys/fs/cgroup/`

4. **Event Storage** (`lanthorn/src/storage.rs`)
   - Uses SQLx with SQLite to store connection events
   - Schema defined in `lanthorn/migrations/` directory
   - Main events table tracks: timestamp, connection info (IP, port, protocol, domain name), process info (PID, cgroup), and Docker container info
   - Separate dns_events table for DNS query auditing

5. **Build Process** (`lanthorn/build.rs`)
   - Automatically compiles the eBPF program during the main crate build
   - Uses `aya-build` to invoke cargo with the correct toolchain and options
   - The eBPF binary is embedded into the userspace binary via `include_bytes_aligned!`

## Development Commands

### Building
```bash
# Standard build (requires sudo to run due to eBPF)
cargo build

# Release build
cargo build --release
```

### Running
```bash
# Run with logging enabled
RUST_LOG=info cargo run --release

# Run with specific features disabled
cargo run --release -- --disable-tcp-mon
cargo run --release -- --disable-dns-mon
cargo run --release -- --disable-docker-mon
cargo run --release -- --db-path /path/to/custom.db
```

Note: The program requires sudo privileges due to eBPF usage. This is configured in `.cargo/config.toml` with `runner = "sudo -E"`.

### Testing
```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p lanthorn
cargo test -p lanthorn-common
```

### Code Quality
```bash
# Check code without building
cargo check

# Format code (uses configuration from rustfmt.toml)
cargo fmt

# Run clippy linter
cargo clippy
```

## Cross-Compilation (macOS to Linux)

The eBPF program requires a Linux target. Cross-compilation from macOS:

```bash
# Prerequisites (see README.md for details):
# - rustup target add ${ARCH}-unknown-linux-musl
# - brew install llvm
# - brew install filosottile/musl-cross/musl-cross
# - cargo install bpf-linker (with --no-default-features on macOS)

# Build for specific architecture
CC=${ARCH}-linux-musl-gcc cargo build --package lanthorn --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

## Important Implementation Details

### Cgroup ID Correlation
The system correlates eBPF events with Docker containers by:
1. eBPF program captures `cgroup_id` using `bpf_get_current_cgroup_id()`
2. Docker monitor reads `/proc/{container_pid}/cgroup` to get cgroup path
3. Gets inode number of `/sys/fs/cgroup/{path}` - this matches the eBPF cgroup_id
4. Maintains an in-memory cache (`DockerCache`) mapping cgroup IDs to container metadata

### Data Flow

**TCP Connection Monitoring:**
1. Kernel: `tcp_connect()` called → eBPF kprobe triggers
2. Kernel: eBPF program writes `ConnectEvent` to EVENTS ring buffer (includes timestamp from `bpf_ktime_get_ns()`)
3. Userspace: `run_tcp_monitor()` reads from ring buffer
4. Userspace: Looks up domain name in DNS cache using destination IP and PID
5. Userspace: Looks up container info from Docker cache using cgroup_id
6. Userspace: Inserts enriched event (with domain name) into SQLite database

**DNS Resolution Tracking:**
1. Userspace: Application calls `getaddrinfo("example.com")` → eBPF uprobe triggers
2. Kernel: eBPF program reads domain name from userspace and writes `DnsEvent` to DNS_EVENTS ring buffer
3. Userspace: `run_dns_monitor()` reads from DNS ring buffer
4. Userspace: Stores query in `PendingDnsCache` indexed by PID (30-second TTL)
5. Userspace: When TCP connection occurs from same PID, correlates IP with domain from pending queries
6. Userspace: Creates IP→domain mapping in `DnsCache` (5-minute TTL) for future lookups
7. Userspace: Optionally stores DNS event in `dns_events` table for auditing

### No-std Constraint
Both `lanthorn-ebpf` and `lanthorn-common` are `no_std` crates because they run in kernel space where the standard library is not available. Only `lanthorn` (userspace) uses std.

### DNS Tracking Implementation Details

**Timestamp Synchronization:**
- Critical: Both `ConnectEvent` and `DnsEvent` use `bpf_ktime_get_ns()` for timestamps
- This ensures consistent time-based correlation between DNS and TCP events
- Using different clock sources (e.g., `SystemTime::now()` vs `bpf_ktime_get_ns()`) will break correlation

**Domain Buffer Size:**
- DNS domain names are limited to 128 bytes in the `DnsEvent` struct
- This is a compromise between eBPF verifier requirements and practical domain name lengths
- Original 256-byte buffer caused eBPF verifier failures
- 128 bytes is sufficient for most domain names (DNS RFC 1035 allows max 253 characters)

**Correlation Strategy:**
- Process-based: Tracks recent DNS queries per PID for 30 seconds
- When TCP connection occurs, looks for DNS queries from same PID within time window
- Falls back to direct IP→domain cache lookup for subsequent connections
- This handles the case where DNS resolution happens before eBPF monitoring starts

**Uprobe vs Kprobe:**
- TCP monitoring uses kprobe (kernel function hook)
- DNS monitoring uses uprobe (userspace function hook on libc's getaddrinfo)
- Uprobe attachment requires symbol resolution (`attach("getaddrinfo", libc_path, None, None)`)
- Tries multiple common libc paths to ensure compatibility across distributions
