// Embedded agent configuration for dynamic probes (DSL)

// Optional: files to stat and file contents to expose
files = ["/etc/ssh/sshd_config", "/etc/hosts", "/home/intar/intar.txt"]
file_content = ["/home/intar/intar.txt"]

// Probes evaluated inside the agent. Results are exported as
// intar_agent_probe{name="<label>",type="<type>"} 1|0

probe "agent_metrics_up" {
  type  = "open_port"
  proto = "tcp"
  port  = 9464
}

probe "sshd_pubkey_auth" {
  type  = "file_regex"
  path  = "/etc/ssh/sshd_config"
  // Capture value of PubkeyAuthentication (yes/no)
  regex = "^\\s*PubkeyAuthentication\\s+(\\S+)"
}

probe "sshd_password_auth" {
  type  = "file_regex"
  path  = "/etc/ssh/sshd_config"
  // Capture value of PasswordAuthentication (yes/no)
  regex = "^\\s*PasswordAuthentication\\s+(\\S+)"
}

probe "sshd_hostkey_ed25519" {
  type  = "file_regex"
  path  = "/etc/ssh/sshd_config"
  // Capture HostKeyAlgorithms line if it contains ssh-ed25519
  regex = "^\\s*HostKeyAlgorithms\\s+.*ssh-ed25519.*$"
}

probe "intar_txt_content" {
  type   = "file_content"
  path   = "/home/intar/intar.txt"
  // Optional cutoff for emitted content length
  cutoff = 200
}
