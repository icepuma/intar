name = "single-ubuntu-vm"
display_name = "Single Ubuntu VM"

description = <<EOF
A minimal single‑VM scenario showcasing intar.
Boots Ubuntu 24.04 LTS and starts with a simple file‑content exercise you can fix via SSH.
Perfect for getting started.
EOF

image = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"

// A reusable problem that groups tools, a manipulation, and probes
problem "file-fixed" {
  description = "Ensure /home/intar/intar.txt contains 'INTAR READY' and harden sshd with modern ciphers"

  tools {
    packages = ["htop", "jq", "yq"]
  }

  // Optional extra setup; runs during cloud-init
  manipulation {
    script = <<EOF
    # Intentionally start in a failing state; fix to pass the probe
    # Avoid trailing newline: use printf, not echo
    printf "INTAR PENDING" > /home/intar/intar.txt
    chown intar:intar /home/intar/intar.txt
    EOF
  }

  // Probe: validate file content equals "INTAR READY"
  probe "intar_txt_fixed" {
    metric = "intar_agent_file_content"
    labels = { path = "/home/intar/intar.txt", content = "INTAR READY" }
    op     = "eq"
    value  = 1
  }

  // Probes: ensure sshd exposes modern ciphers via metrics
  probe "sshd_cipher_chacha20" {
    metric = "intar_agent_setting"
    labels = { subsystem = "sshd", key = "Ciphers", value = "chacha20-poly1305@openssh.com" }
    op     = "eq"
    value  = 1
  }
  probe "sshd_cipher_aes256gcm" {
    metric = "intar_agent_setting"
    labels = { subsystem = "sshd", key = "Ciphers", value = "aes256-gcm@openssh.com" }
    op     = "eq"
    value  = 1
  }
}

vm "vm1" {
  // Keep boot fast: no package manipulations
  // Only reference the problem with the file-content probe
  problems = ["file-fixed"]
}
