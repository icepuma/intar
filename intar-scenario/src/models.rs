use indexmap::IndexMap;
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

    /// Reusable manipulation definitions (labeled HCL blocks)
    /// Usage inside a VM via labeled `manipulation "name" {}` blocks
    #[serde(default, rename = "manipulation")]
    pub manipulations: IndexMap<String, Manipulation>,
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

    #[test]
    fn parse_with_multiple_manipulation_blocks() {
        let hcl = r#"
            name = "ManipDemo"
            image = "https://example.com/x.img"
            manipulation "first" {
              packages = ["curl"]
              script = "echo first"
            }
            manipulation "second" {
              packages = ["jq"]
              script = <<EOF
              echo second
              jq --version || true
              EOF
            }
            vm "toolbox" {
              cpus = 2
              memory = 2048
              manipulations = ["first", "second"]
            }
        "#;
        let s: Scenario = hcl::from_str(hcl).expect("parse");
        let cfg = s.vm.get("toolbox").unwrap();
        assert_eq!(cfg.manipulations, vec!["first", "second"]);
        assert_eq!(s.manipulations.get("first").unwrap().packages, vec!["curl"]);
        assert!(
            s.manipulations
                .get("second")
                .unwrap()
                .script
                .as_ref()
                .unwrap()
                .contains("jq --version")
        );
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
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

    /// References to reusable manipulation definitions by label.
    /// Declare as a simple list: `manipulations = ["tools", "jq"]`.
    #[serde(default)]
    pub manipulations: Vec<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct NetworkConfig {
    /// Static IP address override for the private network interface
    /// If not specified, will be auto-assigned based on VM index
    pub static_ip: Option<String>,

    /// Extra network routes for this VM
    #[serde(default)]
    pub routes: Vec<NetworkRoute>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkRoute {
    /// Destination network (e.g., "192.168.1.0/24")
    pub to: String,

    /// Gateway IP address
    pub via: String,

    /// Route metric (priority)
    #[serde(default = "default_route_metric")]
    pub metric: u32,
}

/// Scenario-defined post-provisioning manipulation block (one script)
#[derive(Debug, Deserialize, Default, Clone)]
pub struct Manipulation {
    /// Packages to install prior to running the manipulation script
    #[serde(default)]
    pub packages: Vec<String>,

    /// Shell script to run (single or multiline)
    /// Runs as root during cloud-init runcmd.
    #[serde(default)]
    pub script: Option<String>,
}

// Empty ref type removed: we now reference by string labels for simplicity

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
