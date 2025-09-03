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
- Lint/format (recommended): `just check` (runs `cargo fmt`, `cargo clippy`, `cargo nextest` if present)
- Logs: `RUST_LOG=info cargo run --bin intar -- scenario run MultiDemo`

## Coding Style & Naming Conventions
- Rust 2024 edition. Use `cargo fmt` and `cargo clippy` before submitting.
- Logging: prefer `tracing` over println/eprintln. Initialize via `tracing-subscriber` in the CLI.
- Progress/UI: use `indicatif` (keep spinner output tidy; no direct prints around it).
- Constants: network ports/IP helpers live in `intar-local-backend/src/constants.rs`.
- Naming: modules/files `snake_case`, types `UpperCamelCase`, functions `snake_case`.

## Testing Guidelines
- The repository currently ships without tests. If you add tests:
  - Use Rust’s test harness (`#[cfg(test)]`) and `tokio::test` for async.
  - Co-locate unit tests with the code they validate.
  - Run with `cargo test` (or `cargo nextest run` if you add nextest).

## Commit & Pull Request Guidelines
- Commits: concise, imperative subject (e.g., “Add UDP hub and tracing”), short body when needed.
- PRs: include description, rationale, and logs/screenshots if UI/logging changed.
- Keep changes focused; prefer small, reviewable PRs. Reference issues where applicable.

## Security & Configuration Tips
- No sudo required. QEMU is the only external dependency.
- Acceleration: macOS `-accel hvf`; Linux `-enable-kvm` (ensure group perms).
- aarch64 firmware is auto-detected; install EDK2 firmware if missing.
- Keys/Data live under platform-specific user data dirs (managed by `directories`).
