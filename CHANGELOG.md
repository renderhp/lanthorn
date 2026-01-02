# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- TCP connection monitoring via eBPF kprobe on `tcp_connect`
- DNS resolution tracking via uprobe on `getaddrinfo` with IP-to-domain correlation
- Docker container correlation using cgroup IDs and container metadata
- Process enrichment capturing process name and command line for each connection
- Threat feed integration with Feodo Tracker (malicious IPs) and URLhaus (malicious domains)
- SQLite database storage with migration support
- CLI with flags to disable individual monitors (`--disable-tcp-mon`, `--disable-dns-mon`, `--disable-docker-mon`, `--disable-threat-feeds`)
- Custom database path via `--db-path` flag
- Continuous Docker container event monitoring (start/stop/die events)
- CI workflow with automated build, lint, and test checks
- Nightly build workflow with cross-compilation for x86_64 and aarch64 Linux

