use anyhow::{Context, Result, bail};
use std::path::PathBuf;

fn detect_linux_target() -> String {
    if let Ok(t) = std::env::var("INTAR_AGENT_TARGET") {
        return t;
    }
    // Default to aarch64 MUSL to match our Linux cloud images and avoid glibc.
    "aarch64-unknown-linux-musl".to_string()
}

fn find_local_agent_in_target() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("Failed to get current working directory")?;
    let target_triple = detect_linux_target();
    let candidates = ["release", "debug"]; // prefer release
    for profile in candidates {
        let p = cwd
            .join("target")
            .join(&target_triple)
            .join(profile)
            .join("intar-agent");
        if p.exists() {
            return Ok(p);
        }
    }
    bail!(
        "intar-agent binary not found under target/{target_triple}/{{release,debug}}.\n  Build it first, e.g.: cargo build -p intar-agent --release --target {target_triple}",
        target_triple = target_triple
    );
}

/// Resolve an agent binary path to use inside the VM.
/// Returns `Some(path)` if `INTAR_AGENT_BUNDLE` is set or `local_agent` is true and a target build exists.
pub fn resolve_agent_path(local_agent: bool) -> Result<Option<PathBuf>> {
    if let Ok(path) = std::env::var("INTAR_AGENT_BUNDLE") {
        return Ok(Some(PathBuf::from(path)));
    }
    if local_agent {
        return Ok(Some(find_local_agent_in_target()?));
    }
    Ok(None)
}
