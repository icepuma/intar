check:
    cargo fmt --all
    # Enable additional Clippy lint groups for deeper checks
    cargo clippy --workspace --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -W clippy::cargo
    cargo nextest run --workspace --all-targets --all-features --status-level pass || cargo test --workspace --all-targets --all-features

# One-step: cross-build the agent for aarch64 MUSL on amd64, then run scenario
run:
    CROSS_CONTAINER_OPTS="--platform linux/amd64" CROSS_BUILD_OPTS="--platform linux/amd64" cross build --bin intar-agent --target aarch64-unknown-linux-musl
    INTAR_AGENT_BUNDLE=target/aarch64-unknown-linux-musl/debug/intar-agent \
    cargo run --bin intar -- scenario run multidemo
