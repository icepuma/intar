name = "multiple-rocky-linux-vms"
display_name = "Multiple Rocky Linux VMs"

description = <<EOF
Multi‑VM scenario demonstrating VM‑to‑VM communication and isolation (Rocky Linux 9).
Includes a simple shared task: set /home/intar/intar.txt to 'INTAR READY' on each VM.
EOF

image = "https://dl.rockylinux.org/pub/rocky/9/images/aarch64/Rocky-9-GenericCloud.latest.aarch64.qcow2"

// Simple problem: manage a whitelisted file in the intar home
problem "file-fixed" {
  description = "Ensure /home/intar/intar.txt contains 'INTAR READY'"

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
  probe "intar_txt_fixed" {
    metric = "intar_agent_file_content"
    labels = { path = "/home/intar/intar.txt", content = "INTAR READY" }
    op     = "eq"
    value  = 1
  }
}

vm "web" {
  problems = ["file-fixed"]
}
vm "db" {
  problems = ["file-fixed"]
}
vm "cache" {
  problems = ["file-fixed"]
}
