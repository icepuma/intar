name = "Demo"

description = <<EOF
This is a demo scenario for testing the intar system.
It demonstrates basic VM configuration with Ubuntu 24.04 LTS.
Perfect for getting started with intar scenarios.
EOF

image = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"

// Reusable named manipulations
manipulation "tools" {
  packages = ["htop"]
  script = "echo 'htop installed'"
}

manipulation "jq-yq" {
  packages = ["jq", "yq"]
  script = <<EOF
  echo 'running second manipulation'
  jq --version || true
  yq --version || true
  EOF
}

manipulation "random-file" {
  script = <<EOF
  # create a random 1KB file for the intar user
  head -c 1024 /dev/urandom > /home/intar/random.bin
  chown intar:intar /home/intar/random.bin
  EOF
}

vm "vm1" {
  manipulations = ["tools", "jq-yq", "random-file"]
}
