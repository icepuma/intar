//! Embedded intar-agent binaries (Linux MUSL) for VM injection.
//!
//! We embed the raw release binaries for both `aarch64` and `x86_64` targets.
//! The paths reference the workspace target dir so building `intar` will
//! fail if the agents have not been built in release mode first.

// aarch64-unknown-linux-musl release agent
pub static AARCH64_AGENT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/aarch64-unknown-linux-musl/release/intar-agent"
));

// x86_64-unknown-linux-musl release agent
pub static X86_64_AGENT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/x86_64-unknown-linux-musl/release/intar-agent"
));

/// Return the embedded agent bytes for the current host architecture.
#[must_use]
pub fn embedded_agent_for_host() -> &'static [u8] {
    match std::env::consts::ARCH {
        "aarch64" => AARCH64_AGENT,
        "x86_64" => X86_64_AGENT,
        _ => {
            // Default to x86_64 to avoid accidental mismatch on uncommon hosts
            X86_64_AGENT
        }
    }
}
