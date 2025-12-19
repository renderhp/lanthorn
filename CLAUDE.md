# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Lanthorn is a network connection monitoring tool that uses eBPF (Extended Berkeley Packet Filter) to track TCP connections at the kernel level. It correlates network activity with Docker containers and stores events in a SQLite database.

## Project Structure

This is a Rust workspace with three crates:

- **lanthorn** - Main userspace application that loads eBPF programs, monitors Docker containers, and stores events
- **lanthorn-ebpf** - eBPF kernel-space program that hooks into `tcp_connect` to capture connection events
- **lanthorn-common** - Shared data structures (primarily `ConnectEvent`) used by both userspace and kernel-space code

### Key Architecture Components

1. **eBPF Monitoring** (`lanthorn/src/monitor/ebpf.rs`)
   - Loads the eBPF program from `lanthorn-ebpf` at runtime
   - Attaches a kprobe to `tcp_connect` kernel function
   - Reads connection events from a ring buffer shared with kernel space
   - Correlates events with Docker containers using cgroup IDs

2. **Docker Monitoring** (`lanthorn/src/monitor/docker.rs`)
   - Maintains a cache mapping cgroup IDs to container metadata
   - Uses the Bollard library to interact with Docker API
   - Resolves cgroup IDs by reading `/proc/{pid}/cgroup` and getting inode numbers from `/sys/fs/cgroup/`

3. **Event Storage** (`lanthorn/src/storage.rs`)
   - Uses SQLx with SQLite to store connection events
   - Schema defined in `lanthorn/migrations/20251215214523_init.sql`
   - Tracks: timestamp, connection info (IP, port, protocol), process info (PID, cgroup), and Docker container info

4. **Build Process** (`lanthorn/build.rs`)
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
1. Kernel: `tcp_connect()` called → eBPF kprobe triggers
2. Kernel: eBPF program writes `ConnectEvent` to ring buffer
3. Userspace: `run_tcp_monitor()` reads from ring buffer
4. Userspace: Looks up container info from Docker cache using cgroup_id
5. Userspace: Inserts complete event into SQLite database

### No-std Constraint
Both `lanthorn-ebpf` and `lanthorn-common` are `no_std` crates because they run in kernel space where the standard library is not available. Only `lanthorn` (userspace) uses std.
