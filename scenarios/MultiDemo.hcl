name = "MultiDemo"

description = <<EOF
Multi-VM scenario for testing VM-to-VM communication and isolation.
Tests networking between multiple VMs in the same scenario.
EOF

image = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"

vm "web" {}
vm "db" {}
vm "cache" {}