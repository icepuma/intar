# Repository Guidelines

## Project Structure & Module Organization
- `intar/`: CLI entrypoint (`src/main.rs`) with scenario commands and progress UI.
- `intar-local-backend/`: QEMU backend and VM orchestration:
  - `src/vm.rs`, `src/backend.rs`: lifecycle, start/stop/cleanup
  - `src/cloud_init.rs`: cloud-init user-data/netplan and /etc/hosts injection
  - `src/constants.rs`: shared ports/IP helpers (use these, no magic numbers)
  - `src/system.rs`, `src/dirs.rs`, `src/ssh.rs`, `src/qmp/`
- `intar-scenario/`: Scenario model + embedded HCL scenarios (`scenarios/*.hcl`).
- `assets/`: images and miscellaneous assets.

## Build, Test, and Development Commands
- Build workspace: `cargo build`
- Run CLI: `cargo run --bin intar -- scenario list|run <Name>|status <Name>|ssh <Name> <vm>`
  - Run is foreground. Stop with Ctrl+C (performs stop + cleanup).
- Lint/format/tests (recommended): `just check`
  - Runs `cargo fmt`, `cargo clippy` with `-W clippy::pedantic -W clippy::nursery -W clippy::cargo`, then tests (`cargo nextest` or `cargo test`).
  - You may see “multiple crate versions” warnings due to transitive deps; these are acceptable.
- Logs: `RUST_LOG=info cargo run --bin intar -- scenario run MultiDemo`

## Coding Style & Naming Conventions
- Rust 2024 edition. Use `cargo fmt` and `cargo clippy` before submitting.
- Logging: prefer `tracing` over println/eprintln. Initialize via `tracing-subscriber` in the CLI.
- Progress/UI: use `indicatif` (keep spinner output tidy; no direct prints around it).
- Constants: network ports/IP helpers live in `intar-local-backend/src/constants.rs`.
- Naming: modules/files `snake_case`, types `UpperCamelCase`, functions `snake_case`.

Additional guidance
- Avoid ad-hoc magic numbers: use helpers from `intar-local-backend/src/constants.rs` (`lan_ip`, `lan_subnet`, `hub_port`, `HOSTFWD_BASE_PORT`).
- Use lossless casts (`u16::from(x)`) and `TryFrom` where appropriate to avoid clippy truncation warnings.
- Keep functions reasonably sized; prefer extracting helpers if a function grows too long (e.g., platform-specific branches).
- Prefer `format!("{var}")` style inline args; clippy prefers this in pedantic mode.

## Testing Guidelines
- Unit tests live alongside code under `#[cfg(test)]` and use `tokio::test` for async.
- Run with `cargo nextest run` (fallback to `cargo test`).

Areas covered by tests
- Cloud-init generators (user-data, network-config, hosts section)
- QMP line codec framing
- Directory layout helpers (`IntarDirs`)
- Constants derivations (`lan_ip`, `hub_port`)

## Commit & Pull Request Guidelines
- Commits: concise, imperative subject (e.g., “Add UDP hub and tracing”), short body when needed.
- PRs: include description, rationale, and logs/screenshots if UI/logging changed.
- Keep changes focused; prefer small, reviewable PRs. Reference issues where applicable.

## Security & Configuration Tips
- No sudo required. QEMU is the only external dependency.
- Acceleration: macOS `-accel hvf`; Linux `-enable-kvm` (ensure group perms).
- aarch64 firmware is auto-detected; install EDK2 firmware if missing.
- Keys/Data live under platform-specific user data dirs (managed by `directories`).

Tools required
- `qemu-system-*` and `qemu-img`
- `ssh` (CLI) for readiness checks and `intar scenario ssh`
- ISO tool for cloud-init seed:
  - macOS: `hdiutil`
  - Linux: one of `genisoimage`, `mkisofs`, or `xorriso`

Runtime env knobs
- `INTAR_QMP_CONNECT_TIMEOUT_MS`, `INTAR_QMP_COMMAND_TIMEOUT_MS` (override QMP timeouts)

Notes
- The per-scenario UDP hub is managed in-process by the backend; there’s no separate hub process to run.
- VM resources (CPUs/memory) are read from the scenario and passed to QEMU.
