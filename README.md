# intar

<div align="center">
  <img src="assets/logo.png" alt="Intar Logo">
</div>

Quickstart (rootless)
- Requirements: `qemu-system-*` in PATH (x86_64 or aarch64). No sudo, no extra networking tools.
- Also required: `qemu-img`, `ssh` (CLI), and an ISO tool (`hdiutil` on macOS, or `genisoimage`/`mkisofs`/`xorriso` on Linux).
- Install tips:
  - macOS (Homebrew): `brew install qemu`
  - Debian/Ubuntu: `sudo apt-get install qemu-system qemu-utils genisoimage` (or `xorriso`)
  - Fedora: `sudo dnf install qemu-system qemu-img genisoimage`
- aarch64 firmware: install EDK2/UEFI (e.g., `edk2-aarch64`); the path is auto-detected.
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
- Resources: taken from scenario (`cpus`, `memory`); defaults `2 CPUs`, `2048 MB`.
- aarch64 firmware is auto-detected; install EDK2 if missing.
- Base images download to the user cache on first run.

Scenario spec (HCL)
- Minimal:
  - `name = "Demo"`
  - `image = "https://.../noble-server-cloudimg-arm64.img"`
  - `vm "vm1" {}`
- Optional:
  - `sha256 = "<sha256-hex>"` verifies the downloaded image
  - VM resources: `vm "web" { cpus = 4 memory = 4096 }`

Manipulations (post-install)
- Define repeated per-VM `manipulation` blocks to run after cloud-init installs packages:
  - All `packages` from all blocks are merged (deduped, order-preserved) and installed first.
  - Each block’s `script` runs as root during `runcmd` in declaration order.
  - Scripts are written to `/var/lib/intar/manipulations-<n>.sh`.

Example:
```
vm "toolbox" {
  cpus = 2
  memory = 2048
  manipulation {
    packages = ["curl"]
    script = "echo first"
  }
  manipulation {
    packages = ["jq"]
    script = <<EOF
    echo second
    jq --version || true
    EOF
  }
}
```

Paths and logs
- Cache images: `~/.cache/intar/images/`
- Scenario data: `~/.local/share/intar/scenarios/<Scenario>/`
- VM data: `.../vms/<VM>/`
  - Disk: `disk.qcow2`
  - Cloud-init: `cloud-init/`
- Runtime (sockets/PIDs/logs): platform runtime dir (Linux: `/run/user/<uid>/...`) or data dir fallback
  - QMP socket: `vm.qmp`
  - PID file: `vm.pid`
  - Log: `vm.log`

Dev workflow
- Lint/format/tests: `just check` (fmt + clippy pedantic/nursery/cargo + tests)
- Run examples:
  - `cargo run --bin intar -- scenario list`
  - `RUST_LOG=info cargo run --bin intar -- scenario run MultiDemo`
  - `cargo run --bin intar -- scenario status MultiDemo`
  - `cargo run --bin intar -- scenario ssh MultiDemo web`

Env knobs
- `INTAR_QMP_CONNECT_TIMEOUT_MS`, `INTAR_QMP_COMMAND_TIMEOUT_MS` to tune QMP timeouts.

Clippy
- You may observe cargo “multiple crate versions” warnings due to transitive deps; acceptable for now.
