name = "Demo"

description = <<EOF
This is a demo scenario for testing the intar system.
It demonstrates basic VM configuration with Ubuntu 24.04 LTS.
Perfect for getting started with intar scenarios.
EOF

image = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"

// A reusable problem that groups tools, a manipulation, and probes
problem "file-fixed" {
  description = "Ensure /home/intar/intar.txt contains 'fixed'"

  tools {
    packages = ["htop", "jq", "yq"]
  }

  // Optional extra setup; runs during cloud-init
  manipulation {
    script = <<EOF
    echo "basic-sshd problem applied" | tee /etc/motd
    # Ensure the marker file contains exact text without newline
    printf "damaged" > /home/intar/intar.txt
    chown intar:intar /home/intar/intar.txt
    EOF
  }

  // Probe: validate file content equals "fixed"
  probe "intar_txt_fixed" {
    metric = "intar_agent_file_content"
    labels = { path = "/home/intar/intar.txt", content = "fixed" }
    op     = "eq"
    value  = 1
  }
}

vm "vm1" {
  // Keep boot fast: no package manipulations
  // Only reference the problem with the file-content probe
  problems = ["file-fixed"]
}
