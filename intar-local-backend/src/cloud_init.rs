use anyhow::{Context, Result};
use std::fmt::Write as _;
use std::path::PathBuf;
use tokio::fs;
use uuid::Uuid;

use crate::constants::lan_ip as calc_lan_ip;
use crate::dirs::IntarDirs;

const DEFAULT_USERNAME: &str = "intar";
const CLOUD_CONFIG_HEADER: &str = "#cloud-config";

/// Cloud-init generator and helpers for a single VM.
pub struct CloudInitConfig {
    pub scenario_name: String,
    pub vm_name: String,
    pub dirs: IntarDirs,
    pub ssh_public_key: String,
    pub vm_index: u8,              // For IP allocation within scenario
    pub scenario_id: u8,           // For scenario network separation
    pub all_vm_names: Vec<String>, // All VM names in the scenario for hostname resolution
    // Manipulations support
    pub manipulation_packages: Vec<String>,
    pub manipulation_scripts: Vec<String>,
}

/// Configuration carrier for `CloudInitConfig::new` to keep the constructor
/// signature concise and future-proof.
#[derive(Clone)]
pub struct CloudInitSpec {
    /// Scenario name this VM belongs to.
    pub scenario_name: String,
    /// VM name within the scenario.
    pub vm_name: String,
    /// Directory layout helper for locating paths.
    pub dirs: IntarDirs,
    /// Authorized SSH public key added for the default user.
    pub ssh_public_key: String,
    /// VM index (0-based) within the scenario for deterministic IPs/ports.
    pub vm_index: u8,
    /// Scenario ID derived from scenario name for network separation.
    pub scenario_id: u8,
    /// All VM names in the scenario for hosts injection.
    pub all_vm_names: Vec<String>,
    /// Packages required by manipulations (merged, deduped, order-preserved).
    pub manipulation_packages: Vec<String>,
    /// Post-install scripts to be executed in order.
    pub manipulation_scripts: Vec<String>,
}

impl CloudInitConfig {
    /// Create a new cloud-init config helper for a VM.
    #[must_use]
    pub fn new(spec: CloudInitSpec) -> Self {
        Self {
            scenario_name: spec.scenario_name,
            vm_name: spec.vm_name,
            dirs: spec.dirs,
            ssh_public_key: spec.ssh_public_key,
            vm_index: spec.vm_index,
            scenario_id: spec.scenario_id,
            all_vm_names: spec.all_vm_names,
            manipulation_packages: spec.manipulation_packages,
            manipulation_scripts: spec.manipulation_scripts,
        }
    }

    /// Get the directory where cloud-init files will be stored for this VM
    /// Directory where cloud-init seed files are stored for this VM.
    #[must_use]
    pub fn get_cloud_init_dir(&self) -> PathBuf {
        self.dirs
            .data_vm_dir(&self.scenario_name, &self.vm_name)
            .join("cloud-init")
    }

    /// Generate MAC addresses for the VM's network interfaces
    /// Generate stable MAC addresses for both NICs.
    #[must_use]
    pub fn generate_mac_addresses(&self) -> (String, String) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Generate consistent MAC addresses based on scenario and VM name
        let mut hasher = DefaultHasher::new();
        self.scenario_name.hash(&mut hasher);
        self.vm_name.hash(&mut hasher);

        // Interface 0 (user networking - for SSH access)
        let mut eth0_hasher = hasher.clone();
        0u8.hash(&mut eth0_hasher);
        let eth0_hash = eth0_hasher.finish();
        let eth0_mac = format!(
            "52:54:00:{:02x}:{:02x}:{:02x}",
            (eth0_hash >> 16) & 0xff,
            (eth0_hash >> 8) & 0xff,
            eth0_hash & 0xff
        );

        // Interface 1 (socket networking - for VM-to-VM communication)
        let mut eth1_hasher = hasher;
        1u8.hash(&mut eth1_hasher);
        let eth1_hash = eth1_hasher.finish();
        let eth1_mac = format!(
            "52:54:00:{:02x}:{:02x}:{:02x}",
            (eth1_hash >> 16) & 0xff,
            (eth1_hash >> 8) & 0xff,
            eth1_hash & 0xff
        );

        (eth0_mac, eth1_mac)
    }

    /// Generate the user-data file content
    ///
    /// Includes:
    /// - default user and SSH key
    /// - package installation (`manipulation_packages`)
    /// - `/etc/hosts` injection for inter-VM name resolution
    /// - one script per manipulation under `/var/lib/intar/manipulations-<n>.sh`
    ///   with a portable bash shebang, invoked in order via `runcmd`.
    #[must_use]
    pub fn generate_user_data(&self) -> String {
        let hostname = format!("{}-{}", self.vm_name, self.scenario_name);
        // Compose packages list (manipulation packages only for now)
        let packages_yaml = if self.manipulation_packages.is_empty() {
            "[]".to_string()
        } else {
            // YAML inline list of strings
            let quoted: Vec<String> = self
                .manipulation_packages
                .iter()
                .map(|p| format!("'{}'", p.replace('\'', "''")))
                .collect();
            format!("[{}]", quoted.join(", "))
        };

        // Prepare write_files for hosts and optional manipulation scripts
        let (host_write_file_item, runcmd_base_yaml) =
            self.generate_hosts_write_files_and_runcmd_items();

        // Optional multiple manipulation scripts write_files and runcmd entries
        let mut manip_write_file_items = String::new();
        let mut manip_runcmd_items = String::new();
        for (i, script) in self.manipulation_scripts.iter().enumerate() {
            let idx = i + 1;
            // Ensure a portable bash shebang is present
            let body = if script.trim_start().starts_with("#!") {
                script.clone()
            } else {
                format!("#!/usr/bin/env bash\n{script}")
            };
            let content = body.replace('\n', "\n      ");
            let path = format!("/var/lib/intar/manipulations-{idx}.sh");
            let _ = write!(
                manip_write_file_items,
                r"  - path: {path}
    owner: root:root
    permissions: '0755'
    content: |
      {content}
"
            );
            let _ = writeln!(manip_runcmd_items, "  - {path}");
        }

        // Compose final YAML
        let mut out = String::new();
        let package_update = if self.manipulation_packages.is_empty() {
            "false"
        } else {
            "true"
        };
        let _ = write!(
            out,
            r"{header}
hostname: {hostname}
manage_etc_hosts: true

# Create the intar user with sudo access
users:
  - name: {username}
    gecos: Intar User
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    groups: sudo
    shell: /bin/bash
    ssh_authorized_keys:
      - {ssh_public_key}

# SSH configuration (faster)
ssh_genkeytypes: [ed25519]
ssh_deletekeys: false
ssh_pwauth: false
disable_root: true

# Package management (faster boot)
package_update: {package_update}
package_upgrade: false
packages: {packages}

# System configuration
timezone: UTC
locale: en_US.UTF-8

",
            header = CLOUD_CONFIG_HEADER,
            hostname = hostname,
            username = DEFAULT_USERNAME,
            ssh_public_key = self.ssh_public_key.trim(),
            packages = packages_yaml,
            package_update = package_update,
        );

        // write_files list
        out.push_str("write_files:\n");
        out.push_str(&host_write_file_item);
        out.push_str(&manip_write_file_items);

        // runcmd section
        out.push_str("runcmd:\n");
        out.push_str(&runcmd_base_yaml);
        out.push_str(&manip_runcmd_items);

        // Final message
        let _ = write!(
            out,
            "# Cloud-init final message\nfinal_message: \"Cloud-init setup complete for {hostname}\"\n"
        );

        out
    }

    /// Generate /etc/hosts entries for all VMs and runcmd items to apply them
    fn generate_hosts_write_files_and_runcmd_items(&self) -> (String, String) {
        // Poor man's DNS via /etc/hosts using deterministic LAN IPs
        let mut all = self.all_vm_names.clone();
        all.sort();

        let mut entries = String::new();
        let _ = writeln!(entries, "# intar hosts (scenario {})", self.scenario_name);

        for (idx, name) in all.iter().enumerate() {
            let idx_u8 = u8::try_from(idx).unwrap_or(u8::MAX);
            let ip = calc_lan_ip(self.scenario_id, idx_u8);
            // Provide multiple aliases: short vm name, vm-scenario, vm.scenario
            let _ = writeln!(
                entries,
                "{} {} {}-{} {}.{}",
                ip, name, name, self.scenario_name, name, self.scenario_name
            );
        }

        // Use write_files to stage a hosts fragment
        let write_file_item = format!(
            r"  - path: /etc/hosts.intar
    owner: root:root
    permissions: '0644'
    content: |
      {entries}
",
            entries = entries.replace('\n', "\n      ")
        );

        // Base runcmd items: append hosts and mask/disable slow services
        let runcmd_items = String::from(concat!(
            "  - bash -c 'grep -q \"^# intar hosts (scenario \" /etc/hosts || cat /etc/hosts.intar >> /etc/hosts'\n",
            "  - systemctl mask systemd-networkd-wait-online.service || true\n",
            "  - systemctl disable --now apt-daily.service apt-daily.timer || true\n",
            "  - systemctl disable --now apt-daily-upgrade.service apt-daily-upgrade.timer || true\n",
            "  - systemctl disable --now motd-news.service motd-news.timer || true\n",
        ));

        (write_file_item, runcmd_items)
    }

    /// Generate the meta-data file content
    /// Generate cloud-init meta-data.
    #[must_use]
    pub fn generate_meta_data(&self) -> String {
        let instance_id = Uuid::new_v4();
        let hostname = format!("{}-{}", self.vm_name, self.scenario_name);
        format!("instance-id: {instance_id}\nlocal-hostname: {hostname}\n")
    }

    /// Generate the network-config file content for rootless dual-NIC setup
    /// Generate netplan YAML for the two NICs.
    #[must_use]
    pub fn generate_network_config(&self) -> String {
        let (eth0_mac, eth1_mac) = self.generate_mac_addresses();

        // Deterministic private LAN IP: 172.30.<scenario_id>.<10+vm_index>
        let lan_ip = calc_lan_ip(self.scenario_id, self.vm_index);

        format!(
            r#"version: 2
ethernets:
  eth0:
    match:
      macaddress: "{eth0_mac}"
    set-name: eth0
    dhcp4: true
    dhcp6: false
    optional: false
    nameservers:
      addresses: [8.8.8.8, 8.8.4.4]
  eth1:
    match:
      macaddress: "{eth1_mac}"
    set-name: eth1
    addresses: ["{lan_ip}/24"]
    dhcp4: false
    dhcp6: false
    optional: false
"#
        )
    }

    /// Create all cloud-init configuration files
    /// Create cloud-init files on disk.
    ///
    /// # Errors
    /// Returns an error if any file write fails.
    pub async fn create_config_files(&self) -> Result<PathBuf> {
        let cloud_init_dir = self.get_cloud_init_dir();

        // Ensure the cloud-init directory exists
        self.dirs
            .ensure_dir(&cloud_init_dir)
            .await
            .context("Failed to create cloud-init directory")?;

        // Generate and write user-data
        let user_data = self.generate_user_data();
        let user_data_path = cloud_init_dir.join("user-data");
        fs::write(&user_data_path, user_data)
            .await
            .context("Failed to write user-data file")?;

        // Generate and write meta-data
        let meta_data = self.generate_meta_data();
        let meta_data_path = cloud_init_dir.join("meta-data");
        fs::write(&meta_data_path, meta_data)
            .await
            .context("Failed to write meta-data file")?;

        // Generate and write network-config
        let network_config = self.generate_network_config();
        let network_config_path = cloud_init_dir.join("network-config");
        fs::write(&network_config_path, network_config)
            .await
            .context("Failed to write network-config file")?;

        tracing::info!(
            "Created cloud-init config for {}/{}",
            self.scenario_name,
            self.vm_name
        );
        tracing::info!("  Directory: {}", cloud_init_dir.display());

        Ok(cloud_init_dir)
    }

    /// Clean up cloud-init configuration files
    /// Remove cloud-init files for this VM.
    ///
    /// # Errors
    /// Returns an error if removal fails unexpectedly.
    pub async fn cleanup(&self) -> Result<()> {
        let cloud_init_dir = self.get_cloud_init_dir();

        if cloud_init_dir.exists() {
            fs::remove_dir_all(&cloud_init_dir).await.with_context(|| {
                format!(
                    "Failed to remove cloud-init directory: {}",
                    cloud_init_dir.display()
                )
            })?;
        }

        Ok(())
    }
}

/// Calculate a stable scenario id from its name.
///
/// Ensures consistent network separation between scenarios.
#[must_use]
/// # Panics
/// Panics only if integer conversion fails, which cannot occur here due to modulo reduction.
pub fn calculate_scenario_id(scenario_name: &str) -> u8 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    scenario_name.hash(&mut hasher);

    // Use the hash to generate a scenario ID between 1 and 254
    // (avoiding 0 and 255 for network reasons)
    u8::try_from((hasher.finish() % 254) + 1).expect("hash modulo 254 + 1 always fits in u8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_config_contains_expected_lan_ip() {
        let dirs = IntarDirs::new().expect("dirs");
        let cfg = CloudInitConfig::new(CloudInitSpec {
            scenario_name: "ScenarioX".into(),
            vm_name: "vm1".into(),
            dirs,
            ssh_public_key: "ssh-rsa AAA...".into(),
            vm_index: 0,
            scenario_id: 42,
            all_vm_names: vec!["vm1".into(), "vm2".into()],
            manipulation_packages: vec![],
            manipulation_scripts: vec![],
        });
        let net = cfg.generate_network_config();
        assert!(net.contains("172.30.42.10/24"), "net={net}");
    }

    #[test]
    fn user_data_contains_hosts_and_sshkey() {
        let dirs = IntarDirs::new().expect("dirs");
        let cfg = CloudInitConfig::new(CloudInitSpec {
            scenario_name: "MultiDemo".into(),
            vm_name: "web".into(),
            dirs,
            ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA".into(),
            vm_index: 0,
            scenario_id: 10,
            all_vm_names: vec!["web".into(), "db".into(), "cache".into()],
            manipulation_packages: vec![],
            manipulation_scripts: vec![],
        });
        let user = cfg.generate_user_data();
        assert!(user.starts_with("#cloud-config"));
        assert!(user.contains("ssh_authorized_keys"));
        // hosts file line for db should be present
        assert!(
            user.contains("db db-MultiDemo db.MultiDemo"),
            "user-data={user}",
        );
    }

    #[test]
    fn user_data_includes_manipulations() {
        let dirs = IntarDirs::new().expect("dirs");
        let cfg = CloudInitConfig::new(CloudInitSpec {
            scenario_name: "ManipDemo".into(),
            vm_name: "toolbox".into(),
            dirs,
            ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA".into(),
            vm_index: 0,
            scenario_id: 7,
            all_vm_names: vec!["toolbox".into()],
            manipulation_packages: vec!["curl".into(), "jq".into()],
            manipulation_scripts: vec!["echo one".into(), "echo two".into()],
        });
        let user = cfg.generate_user_data();
        assert!(user.contains("packages: ['curl', 'jq']"), "{user}");
        assert!(user.contains("/var/lib/intar/manipulations-1.sh"), "{user}");
        assert!(user.contains("/var/lib/intar/manipulations-2.sh"), "{user}");
        assert!(user.contains("runcmd:"), "{user}");
    }

    #[test]
    fn scenario_id_is_in_range() {
        for name in &["a", "b", "MultiDemo", "x"] {
            let id = calculate_scenario_id(name);
            assert!((1..=254).contains(&id));
        }
        // Determinism
        assert_eq!(calculate_scenario_id("same"), calculate_scenario_id("same"));
    }
}
