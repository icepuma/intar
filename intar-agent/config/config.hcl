files = ["/etc/ssh/sshd_config", "/etc/sudoers", "/etc/passwd", "/etc/shadow", "/etc/hosts", "/home/intar/intar.txt"]
file_content = ["/home/intar/intar.txt"]
collect_ports = true
collect_users_groups = true

probe "sshd_ciphers_from_files" {
  type         = "kv_list"
  sources      = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"]
  entry_regex  = "^\\s*(?P<key>[A-Za-z][A-Za-z0-9]+)\\s+(?P<values>.+)$"
  include_keys = ["Ciphers"]
  split_regex  = "[,\\s]+"
  labels       = { subsystem = "sshd" }
}
