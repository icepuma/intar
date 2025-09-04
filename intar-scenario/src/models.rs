use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct Scenario {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub image: String,
    /// Optional SHA256 checksum of the image for integrity verification
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub vm: HashMap<String, VmConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_scenario_defaults() {
        let hcl = r#"
            name = "Demo"
            image = "https://example.com/image.qcow2"
            vm "vm1" {}
        "#;
        let s: Scenario = hcl::from_str(hcl).expect("parse");
        assert_eq!(s.name, "Demo");
        assert_eq!(s.sha256, None);
        let cfg = s.vm.get("vm1").unwrap();
        assert_eq!(cfg.cpus, 2);
        assert_eq!(cfg.memory, 2048);
    }

    #[test]
    fn parse_with_overrides_and_sha256() {
        let hcl = r#"
            name = "X"
            image = "https://example.com/x.img"
            sha256 = "deadbeef"
            vm "a" {
              cpus = 4
              memory = 4096
            }
        "#;
        let s: Scenario = hcl::from_str(hcl).expect("parse");
        assert_eq!(s.sha256.as_deref(), Some("deadbeef"));
        let cfg = s.vm.get("a").unwrap();
        assert_eq!(cfg.cpus, 4);
        assert_eq!(cfg.memory, 4096);
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct VmConfig {
    /// Number of CPUs for this VM (defaults to 2)
    #[serde(default = "default_cpus")]
    pub cpus: u8,

    /// Memory in MB for this VM (defaults to 2048)
    #[serde(default = "default_memory")]
    pub memory: u32,

    /// Custom SSH authorized keys for this specific VM (optional)
    #[serde(default)]
    pub ssh_authorized_keys: Vec<String>,

    /// Custom network configuration for this VM (optional)
    #[serde(default)]
    pub network: Option<NetworkConfig>,
}

#[derive(Debug, Deserialize, Default)]
pub struct NetworkConfig {
    /// Static IP address override for the private network interface
    /// If not specified, will be auto-assigned based on VM index
    pub static_ip: Option<String>,

    /// Extra network routes for this VM
    #[serde(default)]
    pub routes: Vec<NetworkRoute>,
}

#[derive(Debug, Deserialize)]
pub struct NetworkRoute {
    /// Destination network (e.g., "192.168.1.0/24")
    pub to: String,

    /// Gateway IP address
    pub via: String,

    /// Route metric (priority)
    #[serde(default = "default_route_metric")]
    pub metric: u32,
}

// Default values
const fn default_cpus() -> u8 {
    2
}

const fn default_memory() -> u32 {
    2048
}

const fn default_route_metric() -> u32 {
    100
}
