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
    // Agent embedding
    pub agent_bundle_gz_b64: Option<String>,
    pub agent_sha256_hex: Option<String>,
    pub agent_otlp_endpoint: Option<String>,
    pub agent_metadata_url: Option<String>,
    pub agent_from_iso: bool,
    pub agent_iso_label: Option<String>,
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
    /// Optional embedded agent (gz+b64) and checksum.
    pub agent_bundle_gz_b64: Option<String>,
    pub agent_sha256_hex: Option<String>,
    /// Optional OTLP HTTP endpoint override for agent.
    pub agent_otlp_endpoint: Option<String>,
    /// Optional metadata discovery URL for the agent (host-side server).
    pub agent_metadata_url: Option<String>,
    /// If true, mount an ISO volume and copy agent from it instead of embedding.
    pub agent_from_iso: bool,
    /// ISO volume label to mount (e.g., "INTARAGENT").
    pub agent_iso_label: Option<String>,
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
            agent_bundle_gz_b64: spec.agent_bundle_gz_b64,
            agent_sha256_hex: spec.agent_sha256_hex,
            agent_otlp_endpoint: spec.agent_otlp_endpoint,
            agent_metadata_url: spec.agent_metadata_url,
            agent_from_iso: spec.agent_from_iso,
            agent_iso_label: spec.agent_iso_label,
        }
    }

    fn packages_yaml_and_update(&self) -> (String, &'static str) {
        if self.manipulation_packages.is_empty() {
            ("[]".to_string(), "false")
        } else {
            let quoted: Vec<String> = self
                .manipulation_packages
                .iter()
                .map(|p| format!("'{}'", p.replace('\'', "''")))
                .collect();
            (format!("[{}]", quoted.join(", ")), "true")
        }
    }

    fn generate_manip_write_files_and_runcmd(&self) -> (String, String) {
        let mut write_files = String::new();
        let mut runcmd = String::new();
        for (i, script) in self.manipulation_scripts.iter().enumerate() {
            let idx = i + 1;
            let body = if script.trim_start().starts_with("#!") {
                script.clone()
            } else {
                format!("#!/usr/bin/env bash\n{script}")
            };
            let content = body.replace('\n', "\n      ");
            let path = format!("/var/lib/intar/manipulations-{idx}.sh");
            let _ = write!(
                write_files,
                r"  - path: {path}
    owner: root:root
    permissions: '0755'
    content: |
      {content}
"
            );
            let _ = writeln!(runcmd, "  - {path}");
        }
        (write_files, runcmd)
    }

    fn compose_base_user_header(
        &self,
        hostname: &str,
        packages_yaml: &str,
        package_update: &'static str,
    ) -> String {
        format!(
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

# SSH configuration (ensure host keys + key-only auth)
# Generate only ED25519 host keys for faster boot
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
        )
    }

    fn append_agent_write_files(&self, out: &mut String) {
        if self.agent_bundle_gz_b64.is_some() {
            if let Some(agent_wf) = self.generate_agent_write_files_embed() {
                out.push_str(&agent_wf);
            }
        } else if let Some(agent_wf) = self.generate_agent_unit_file_only() {
            out.push_str(&agent_wf);
        }
    }

    // bootcmd path removed: agent starts via runcmd only

    fn append_agent_runcmd(&self, out: &mut String) {
        if self.agent_bundle_gz_b64.is_some() {
            out.push_str(
                "  - systemctl daemon-reload\n  - systemctl enable --now intar-agent.service\n",
            );
        } else if self.agent_from_iso {
            let label = self
                .agent_iso_label
                .clone()
                .unwrap_or_else(|| "INTARAGENT".to_string());
            let copy_cmds = format!(
                concat!(
                    "  - mkdir -p /mnt/intar-agent\n",
                    "  - bash -c 'mount -L {label} /mnt/intar-agent || (blkid -L {label} && mount $(blkid -L {label}) /mnt/intar-agent)'\n",
                    "  - cp /mnt/intar-agent/intar-agent /usr/local/bin/intar-agent\n",
                    "  - chmod 0755 /usr/local/bin/intar-agent\n",
                    "  - systemctl daemon-reload\n",
                    "  - systemctl enable --now intar-agent.service\n"
                ),
                label = label
            );
            out.push_str(&copy_cmds);
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
        // Compose packages list and update flag
        let (packages_yaml, package_update) = self.packages_yaml_and_update();

        // Prepare write_files for hosts and optional manipulation scripts
        let (host_write_file_item, runcmd_base_yaml) =
            self.generate_hosts_write_files_and_runcmd_items();

        // Optional multiple manipulation scripts write_files and runcmd entries
        let (manip_write_file_items, manip_runcmd_items) =
            self.generate_manip_write_files_and_runcmd();

        // Compose final YAML header
        let mut out = self.compose_base_user_header(&hostname, &packages_yaml, package_update);

        // bootcmd: mask/disable Snap early to prevent activation
        out.push_str("bootcmd:\n");
        out.push_str(
            concat!(
                "  - systemctl mask snapd.service snapd.seeded.service snapd.apparmor.service snapd.socket || true\n",
                "  - systemctl disable --now snapd.service snapd.seeded.service snapd.apparmor.service snapd.socket || true\n",
                // Also prevent other noisy/slow services from activating early
                "  - systemctl mask pollinate.service pollinate.timer ModemManager.service || true\n",
                "  - systemctl disable --now pollinate.service pollinate.timer ModemManager.service || true\n",
                // Explicitly mask unattended-upgrades to avoid background APT work
                "  - systemctl mask unattended-upgrades.service || true\n",
                "  - systemctl disable --now unattended-upgrades.service || true\n",
            ),
        );

        // write_files list
        out.push_str("write_files:\n");
        // Restrict datasources via a cloud.cfg.d snippet to avoid user-data schema warnings
        out.push_str(
            "  - path: /etc/cloud/cloud.cfg.d/99-intar-datasource.cfg\n    owner: root:root\n    permissions: '0644'\n    content: |\n      datasource_list: [NoCloud]\n",
        );
        out.push_str(&host_write_file_item);
        out.push_str(&manip_write_file_items);
        self.append_agent_write_files(&mut out);

        // runcmd section (start agent as early as possible for ISO case)
        out.push_str("runcmd:\n");
        // 1) Start agent first (mount/copy if from ISO, then enable/start)
        self.append_agent_runcmd(&mut out);
        // 2) Base system tweaks and hosts entries
        out.push_str(&runcmd_base_yaml);
        // Ensure SSH daemon is enabled/started (covers Debian/Ubuntu and RHEL/Fedora)
        out.push_str(
            "  - bash -c 'systemctl enable --now ssh || systemctl enable --now sshd || true'\n",
        );
        // 3) Manipulation scripts last
        out.push_str(&manip_runcmd_items);

        // Final message
        let _ = write!(
            out,
            "# Cloud-init final message\nfinal_message: \"Cloud-init setup complete for {hostname}\"\n"
        );

        out
    }

    fn generate_agent_write_files_embed(&self) -> Option<String> {
        let bundle = self.agent_bundle_gz_b64.as_ref()?;
        let endpoint = self
            .agent_otlp_endpoint
            .clone()
            .unwrap_or_else(|| "http://10.0.2.2:4318/v1/metrics".to_string());
        let md_url = self.agent_metadata_url.clone().unwrap_or_else(|| {
            let port = crate::constants::metadata_port(self.scenario_id);
            format!("http://10.0.2.2:{port}/agent-config")
        });

        let exec_args = if self.agent_otlp_endpoint.is_some() {
            format!(" --otlp-endpoint {endpoint}")
        } else {
            String::new()
        };
        // Agent interval: allow host to override via INTAR_AGENT_INTERVAL_SEC, default to 1s for snappy updates
        let interval =
            std::env::var("INTAR_AGENT_INTERVAL_SEC").unwrap_or_else(|_| "1".to_string());
        let unit = format!(
            r"[Unit]
Description=Intar Agent
After=local-fs.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
Environment=INTAR_METADATA_URL={md_url}
ExecStart=/usr/local/bin/intar-agent --interval {interval}{exec_args}
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
"
        );

        let mut out = String::new();
        // Binary file
        let _ = write!(
            out,
            r"  - path: /usr/local/bin/intar-agent
    owner: root:root
    permissions: '0755'
    encoding: gz+b64
    content: '{bundle}'
"
        );
        // Unit file
        let _ = write!(
            out,
            r"  - path: /etc/systemd/system/intar-agent.service
    owner: root:root
    permissions: '0644'
    content: |
      {unit}
",
            unit = unit.replace('\n', "\n      ")
        );
        Some(out)
    }

    fn generate_agent_unit_file_only(&self) -> Option<String> {
        if !self.agent_from_iso {
            return None;
        }
        let endpoint = self
            .agent_otlp_endpoint
            .clone()
            .unwrap_or_else(|| "http://10.0.2.2:4318/v1/metrics".to_string());
        let md_url = self.agent_metadata_url.clone().unwrap_or_else(|| {
            let port = crate::constants::metadata_port(self.scenario_id);
            format!("http://10.0.2.2:{port}/agent-config")
        });

        let exec_args = if self.agent_otlp_endpoint.is_some() {
            format!(" --otlp-endpoint {endpoint}")
        } else {
            String::new()
        };
        // Agent interval: allow host to override via INTAR_AGENT_INTERVAL_SEC, default to 1s for snappy updates
        let interval =
            std::env::var("INTAR_AGENT_INTERVAL_SEC").unwrap_or_else(|_| "1".to_string());
        let unit = format!(
            r"[Unit]
Description=Intar Agent
After=local-fs.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
Environment=INTAR_METADATA_URL={md_url}
ExecStart=/usr/local/bin/intar-agent --interval {interval}{exec_args}
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
"
        );

        let mut out = String::new();
        let _ = write!(
            out,
            r"  - path: /etc/systemd/system/intar-agent.service
    owner: root:root
    permissions: '0644'
    content: |
      {unit}
",
            unit = unit.replace('\n', "\n      ")
        );
        Some(out)
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
            // Disable additional units that slow or clutter boot
            "  - systemctl mask pollinate.service pollinate.timer ModemManager.service || true\n",
            "  - systemctl disable --now pollinate.service pollinate.timer ModemManager.service || true\n",
            // Also ensure unattended-upgrades is masked/disabled late if present
            "  - systemctl mask unattended-upgrades.service || true\n",
            "  - systemctl disable --now unattended-upgrades.service || true\n",
            // Mask and stop Snap to avoid boot overhead
            "  - systemctl mask snapd.service snapd.seeded.service snapd.apparmor.service || true\n",
            "  - systemctl disable --now snapd.service snapd.seeded.service snapd.apparmor.service || true\n",
            // Ensure SSH daemon is enabled and started (covers Debian/Ubuntu and RHEL/Fedora)
            "  - bash -c 'systemctl enable --now ssh || systemctl enable --now sshd || true'\n",
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
            agent_bundle_gz_b64: None,
            agent_sha256_hex: None,
            agent_otlp_endpoint: None,
            agent_metadata_url: None,
            agent_from_iso: false,
            agent_iso_label: None,
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
            agent_bundle_gz_b64: None,
            agent_sha256_hex: None,
            agent_otlp_endpoint: None,
            agent_metadata_url: None,
            agent_from_iso: false,
            agent_iso_label: None,
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
            agent_bundle_gz_b64: None,
            agent_sha256_hex: None,
            agent_otlp_endpoint: None,
            agent_metadata_url: None,
            agent_from_iso: false,
            agent_iso_label: None,
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
