name = "MultiDemo"

description = <<EOF
Multi-VM scenario for testing VM-to-VM communication and isolation.
Tests networking between multiple VMs in the same scenario.
EOF

image = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"

// Simple problem: manage a whitelisted file in the intar home
problem "motd-welcome" {
  description = "Ensure /home/intar/intar.txt contains the expected text"

  // Minimal manipulation only; no tools or probes
  manipulation {
    script = <<EOF
    # Intentionally set a non-matching value so the probe starts failing
    # Learners can change it to match the probe ("INTAR READY").
    printf "INTAR PENDING" > /home/intar/intar.txt
    chown intar:intar /home/intar/intar.txt
    EOF
  }

  // Probe: verify /home/intar/intar.txt content is set as expected
  probe "motd_set" {
    metric = "intar_agent_file_content"
    labels = { path = "/home/intar/intar.txt", content = "INTAR READY" }
    op     = "eq"
    value  = 1
  }
}

vm "web" {
  problems = ["motd-welcome"]
}
vm "db" {
  problems = ["motd-welcome"]
}
vm "cache" {
  problems = ["motd-welcome"]
}
