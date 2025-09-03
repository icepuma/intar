# intar

<div align="center">
  <img src="assets/logo.png" alt="Intar Logo">
</div>

Quickstart (rootless)
- Requirements: `qemu-system-*` in PATH (x86_64 or aarch64). No sudo, no extra networking tools.
- Run (foreground): `cargo run --bin intar -- scenario run MultiDemo`
  - Press Ctrl+C to stop. Shutdown + cleanup run automatically.
- SSH into a VM: `cargo run --bin intar -- scenario ssh MultiDemo web`
- Status: `cargo run --bin intar -- scenario status MultiDemo`

Networking model
- Dual NIC per VM:
  - NAT NIC: host port forwarding for SSH (`127.0.0.1:2700 + index` -> guest `22`).
  - Private LAN NIC: rootless L2 via built‑in UDP hub on localhost; all VMs join the same bus.
- Inter-VM network: `172.30.<scenario_id>.0/24`, where `<scenario_id>` is derived from scenario name.
- VM LAN IPs: `172.30.<scenario_id>.(10 + index)`; e.g. first VM gets `.10`, second `.11`, etc.
- Poor man’s DNS: `/etc/hosts` is appended with entries like `cache cache-MultiDemo cache.MultiDemo` for each VM.

Examples
- SSH from host: `ssh -i ~/.local/share/intar/scenarios/<Scenario>/ssh-keys/id_ed25519 -p 2700 intar@127.0.0.1`
- Ping between VMs (from within a VM): `ping 172.30.<sid>.11`
 - Name-based ping (from within a VM): `ping db` or `ping db.<Scenario>`

Notes
- Foreground run shows progress spinners; logs via `tracing` (set `RUST_LOG=info`).
- Acceleration: macOS `-accel hvf`; Linux `-enable-kvm -cpu host` (ensure permissions).
- Resources: `-smp 1`, `-m 1024M` per VM by default.
- aarch64 firmware is auto-detected; install EDK2 if missing.
- Base images download to the user cache on first run.
