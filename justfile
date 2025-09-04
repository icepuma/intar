check:
    cargo fmt --all
    # Enable additional Clippy lint groups for deeper checks
    cargo clippy --workspace --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -W clippy::cargo
    cargo nextest run --workspace --all-targets --all-features --status-level pass || cargo test --workspace --all-targets --all-features
