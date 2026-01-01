# Lanthorn

[![CI](https://github.com/renderhp/lanthorn/actions/workflows/ci.yml/badge.svg)](https://github.com/renderhp/lanthorn/actions/workflows/ci.yml)

A lightweight network monitoring tool that tracks TCP connections and correlates them with Docker containers. Lanthorn uses eBPF (Extended Berkeley Packet Filter) to efficiently capture network activity at the kernel level.

## What does it do?

Lanthorn monitors all TCP connections on your Linux system and automatically identifies which Docker containers are making those connections. It also tracks DNS resolutions to enrich connection events with domain names. All events are stored in a SQLite database for analysis and auditing.

**Key Features:**
- Real-time TCP connection monitoring using eBPF
- DNS resolution tracking to map IPs to domain names
- Automatic correlation with Docker containers
- Low overhead kernel-level tracking
- SQLite database for event storage and queries
- Captures connection metadata: destination IP, port, domain name, process ID, container info

## Quick Start

### Prerequisites

- Linux system (eBPF requires Linux kernel)
- Rust toolchains: `rustup toolchain install stable nightly --component rust-src`
- bpf-linker: `cargo install bpf-linker`
- Docker (optional, for container correlation)
- Sudo privileges (required for eBPF)

### Running

```bash
# Build and run with logging
RUST_LOG=info cargo run --release
```

The program will:
1. Start monitoring TCP connections via eBPF
2. Track DNS resolutions to correlate IPs with domain names
3. Scan running Docker containers
4. Store enriched connection events to `lanthorn.db` (SQLite)
5. Run until you press Ctrl+C

## Building

```bash
# Development build
cargo build

# Release build
cargo build --release

# Run tests
cargo test
```
