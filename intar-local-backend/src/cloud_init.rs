use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::fs;
use uuid::Uuid;

use crate::constants::lan_ip as calc_lan_ip;
use crate::dirs::IntarDirs;

const DEFAULT_USERNAME: &str = "intar";
const CLOUD_CONFIG_HEADER: &str = "#cloud-config";

pub struct CloudInitConfig {
    pub scenario_name: String,
    pub vm_name: String,
    pub dirs: IntarDirs,
    pub ssh_public_key: String,
    pub vm_index: u8,              // For IP allocation within scenario
    pub scenario_id: u8,           // For scenario network separation
    pub all_vm_names: Vec<String>, // All VM names in the scenario for hostname resolution
}

impl CloudInitConfig {
    pub fn new(
        scenario_name: String,
        vm_name: String,
        dirs: IntarDirs,
        ssh_public_key: String,
        vm_index: u8,
        scenario_id: u8,
        all_vm_names: Vec<String>,
    ) -> Self {
        Self {
            scenario_name,
            vm_name,
            dirs,
            ssh_public_key,
            vm_index,
            scenario_id,
            all_vm_names,
        }
    }

    /// Get the directory where cloud-init files will be stored for this VM
    pub fn get_cloud_init_dir(&self) -> PathBuf {
        self.dirs
            .data_vm_dir(&self.scenario_name, &self.vm_name)
            .join("cloud-init")
    }

    /// Generate MAC addresses for the VM's network interfaces
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
    pub fn generate_user_data(&self) -> String {
        let hostname = format!("{}-{}", self.vm_name, self.scenario_name);

        format!(
            r#"{header}
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
package_update: false
package_upgrade: false
packages: []

# System configuration
timezone: UTC
locale: en_US.UTF-8

{hosts_config}

# Cloud-init final message
final_message: "Cloud-init setup complete for {hostname}"
"#,
            header = CLOUD_CONFIG_HEADER,
            hostname = hostname,
            username = DEFAULT_USERNAME,
            ssh_public_key = self.ssh_public_key.trim(),
            hosts_config = self.generate_hosts_config(),
        )
    }

    /// Generate /etc/hosts entries for all VMs in the scenario
    fn generate_hosts_config(&self) -> String {
        // Poor man's DNS via /etc/hosts using deterministic LAN IPs
        let mut all = self.all_vm_names.clone();
        all.sort();

        let mut entries = String::new();
        entries.push_str(&format!(
            "# intar hosts (scenario {})\n",
            self.scenario_name
        ));

        for (idx, name) in all.iter().enumerate() {
            let ip = calc_lan_ip(self.scenario_id, idx as u8);
            // Provide multiple aliases: short vm name, vm-scenario, vm.scenario
            let line = format!(
                "{} {} {}-{} {}.{}\n",
                ip, name, name, self.scenario_name, name, self.scenario_name
            );
            entries.push_str(&line);
        }

        // Use write_files to stage a hosts fragment and runcmd to append and mask slow services
        format!(
            r#"write_files:
  - path: /etc/hosts.intar
    owner: root:root
    permissions: '0644'
    content: |
      {entries}
runcmd:
  - bash -c 'grep -q "^# intar hosts (scenario " /etc/hosts || cat /etc/hosts.intar >> /etc/hosts'
  - systemctl mask systemd-networkd-wait-online.service || true
  - systemctl disable --now apt-daily.service apt-daily.timer || true
  - systemctl disable --now apt-daily-upgrade.service apt-daily-upgrade.timer || true
  - systemctl disable --now motd-news.service motd-news.timer || true
"#,
            entries = entries.replace("\n", "\n      ")
        )
    }

    /// Generate the meta-data file content
    pub fn generate_meta_data(&self) -> String {
        let instance_id = Uuid::new_v4();
        let hostname = format!("{}-{}", self.vm_name, self.scenario_name);

        format!(
            r#"instance-id: {instance_id}
local-hostname: {hostname}
"#,
            instance_id = instance_id,
            hostname = hostname,
        )
    }

    /// Generate the network-config file content for rootless dual-NIC setup
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
"#,
            eth0_mac = eth0_mac,
            eth1_mac = eth1_mac,
            lan_ip = lan_ip,
        )
    }

    /// Create all cloud-init configuration files
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

    /// Get the network subnet for this scenario (socket_vmnet shared network)
    pub fn get_scenario_subnet(&self) -> String {
        "192.168.105.0/24".to_string()
    }

    /// Clean up cloud-init configuration files
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

/// Helper function to calculate scenario ID from scenario name
/// This ensures consistent network separation between scenarios
pub fn calculate_scenario_id(scenario_name: &str) -> u8 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    scenario_name.hash(&mut hasher);

    // Use the hash to generate a scenario ID between 1 and 254
    // (avoiding 0 and 255 for network reasons)
    ((hasher.finish() % 254) + 1) as u8
}

// tests removed
