name = "Demo"

description = <<EOF
This is a demo scenario for testing the intar system.
It demonstrates basic VM configuration with Ubuntu 24.04 LTS.
Perfect for getting started with intar scenarios.
EOF

image = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"

vm "vm1" {}
