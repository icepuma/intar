check:
    cargo fmt --all
    # Enable additional Clippy lint groups for deeper checks
    cargo clippy --workspace --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -W clippy::cargo
    cargo nextest run --workspace --all-targets --all-features --status-level pass || cargo test --workspace --all-targets --all-features


build-agents:
    # Build both agent binaries in release mode for embedding
    RUSTFLAGS="-C strip=symbols -C panic=abort -C lto=thin -C embed-bitcode=yes -C codegen-units=1" CROSS_CONTAINER_OPTS="--platform linux/amd64" CROSS_BUILD_OPTS="--platform linux/amd64" cross build --release --bin intar-agent --target aarch64-unknown-linux-musl
    RUSTFLAGS="-C strip=symbols -C panic=abort -C lto=thin -C embed-bitcode=yes -C codegen-units=1" CROSS_CONTAINER_OPTS="--platform linux/amd64" CROSS_BUILD_OPTS="--platform linux/amd64" cross build --release --bin intar-agent --target x86_64-unknown-linux-musl

# Build agents, then run the single-VM Ubuntu scenario
run-single-ubuntu-vm: build-agents
    cargo run --bin intar -- scenario run single-ubuntu-vm

# Build agents, then run the multiple Rocky Linux VMs scenario
run-multiple-rocky-linux-vms: build-agents
    cargo run --bin intar -- scenario run multiple-rocky-linux-vms
