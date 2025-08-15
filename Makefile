# Planet Scale DNS Server Build System

.PHONY: all build release test bench clean install-deps generate-schemas docker

# Default target
all: build

# Install build dependencies
install-deps:
	@echo "Installing build dependencies..."
	@which flatc > /dev/null || (echo "Installing FlatBuffers compiler..." && \
		curl -L https://github.com/google/flatbuffers/releases/download/v23.5.26/Linux.flatc.binary.clang++-12.zip -o flatc.zip && \
		unzip flatc.zip && sudo mv flatc /usr/local/bin/ && rm flatc.zip)
	@rustup component add clippy rustfmt
	@cargo install cargo-criterion cargo-flamegraph

# Generate FlatBuffers schemas
generate-schemas:
	@echo "Generating FlatBuffers schemas..."
	@mkdir -p src/generated
	@flatc --rust --gen-mutable --gen-object-api --filename-suffix "" -o src/generated schemas/dns.fbs

# Development build
build: generate-schemas
	@echo "Building in debug mode..."
	@cargo build

# Optimized release build
release: generate-schemas
	@echo "Building optimized release..."
	@RUSTFLAGS="-C target-cpu=native -C target-feature=+avx2,+fma" cargo build --release

# Release build with debug info for profiling
release-debug: generate-schemas
	@echo "Building release with debug info..."
	@cargo build --profile release-with-debug

# Run tests
test:
	@echo "Running tests..."
	@cargo test --workspace

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	@cargo criterion

# Performance profiling
profile: release-debug
	@echo "Running performance profile..."
	@cargo flamegraph --bin planet-dns -- --config examples/config.toml

# Code formatting
fmt:
	@echo "Formatting code..."
	@cargo fmt --all

# Linting
lint:
	@echo "Running clippy..."
	@cargo clippy --workspace --all-targets --all-features -- -D warnings

# Security audit
audit:
	@echo "Running security audit..."
	@cargo audit

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@cargo clean
	@rm -rf src/generated

# Install binary
install: release
	@echo "Installing planet-dns binary..."
	@cargo install --path crates/dns-server --force

# Docker build
docker:
	@echo "Building Docker image..."
	@docker build -t planet-dns:latest .

# Development setup
dev-setup: install-deps generate-schemas
	@echo "Setting up development environment..."
	@cargo build
	@echo "Development environment ready!"

# CI/CD targets
ci-test: generate-schemas
	@cargo test --workspace --all-features
	@cargo clippy --workspace --all-targets --all-features -- -D warnings
	@cargo fmt --all -- --check

ci-build: generate-schemas
	@cargo build --release --all-features

# Performance testing
perf-test: release
	@echo "Running performance tests..."
	@./scripts/perf-test.sh

# Memory usage analysis
memory-test: release-debug
	@echo "Running memory analysis..."
	@valgrind --tool=massif --stacks=yes ./target/release-with-debug/planet-dns --config examples/config.toml