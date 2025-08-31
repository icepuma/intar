check:
    cargo fmt --all
    cargo clippy --workspace --all-targets --all-features
    cargo nextest run --workspace --all-targets --all-features --no-tests=pass