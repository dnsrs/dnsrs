# DNSRS

A high-performance, planet-scale DNS server implementation in Rust with zero-copy operations, atomic data structures, and unlimited clustering capabilities.

## Features

- **Zero-Copy Operations**: Uses FlatBuffers for serialization without memory allocation overhead
- **Atomic Data Structures**: Lock-free operations for maximum concurrency
- **Planet-Scale Clustering**: Unlimited horizontal scaling with consistent hashing
- **Multiple Protocols**: UDP, TCP, DNS over HTTPS (DoH), DNS over TLS (DoT), DNS over QUIC (DoQ)
- **Advanced Ad-Blocking**: Pi-hole compatible with SIMD-optimized pattern matching
- **DNSSEC Support**: Full DNSSEC validation and signing capabilities
- **High Performance**: Sub-millisecond response times with SIMD optimizations

## Architecture

The server is built with a modular architecture:

- `dns-core`: Core types, error handling, and utilities
- `dns-protocol`: DNS protocol implementations for all transports
- `dns-storage`: Zero-copy storage engine with FlatBuffers
- `dns-cluster`: Planet-scale clustering and replication
- `dns-api`: REST API for management and monitoring
- `dns-server`: Main server binary

## Quick Start

### Prerequisites

- Rust 1.75 or later
- FlatBuffers compiler (`flatc`)

### Installation

```bash
# Install dependencies
make install-deps

# Build the project
make build

# Run in development mode
cargo run --bin dnsrs

# Build optimized release
make release
```

### Configuration

The server can be configured via TOML files, environment variables, or command-line arguments:

```toml
[server]
bind_address = "0.0.0.0"
port = 53
max_connections = 10000

[storage]
data_dir = "./data"
cache_size_mb = 1024

[cluster]
enabled = false

[api]
enabled = true
bind_address = "127.0.0.1"
port = 8080
```

## Performance

The server is designed for extreme performance:

- **Zero-copy operations** eliminate memory allocation overhead
- **Atomic data structures** provide lock-free concurrency
- **SIMD optimizations** accelerate string matching and hashing
- **Memory-mapped storage** enables zero-copy disk access
- **Pre-built responses** serve common queries without processing

Benchmarks show:
- Sub-millisecond response times for cached queries
- 1M+ queries per second on modern hardware
- Linear scaling with CPU cores
- Minimal memory allocation during query processing

## Development

### Building

```bash
# Development build
make build

# Release build with optimizations
make release

# Run tests
make test

# Run benchmarks
make bench

# Format code
make fmt

# Run linter
make lint
```

### Project Structure

```
├── crates/
│   ├── dns-core/          # Core types and utilities
│   ├── dns-protocol/      # Protocol implementations
│   ├── dns-storage/       # Storage engine
│   ├── dns-cluster/       # Clustering
│   ├── dns-api/           # REST API
│   └── dns-server/        # Main server
├── schemas/               # FlatBuffers schemas
├── examples/              # Example configurations
└── docs/                  # Documentation
```

## License

Licensed under Apache License, Version 2.0 ([LICENSE](LICENSE))