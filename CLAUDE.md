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

### Installing dependencies (required to build, run if build fails)
```bash
# install necessary toolchains
rustup toolchain install stable nightly --component rust-src
# install bpf-linker
cargo install bpf-linker
```

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

### Code Quality (run and address all issues before every commit)
```bash
# Check code without building
cargo check

# Format code (uses configuration from rustfmt.toml)
cargo fmt

# Run clippy linter
cargo clippy
```
