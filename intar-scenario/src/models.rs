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
    /// Optional agent OTLP/HTTP endpoint; if set, baked into the agent systemd unit.
    #[serde(default)]
    pub agent_otlp_endpoint: Option<String>,
    /// If true, load intar-agent from local `target/<target>/{release,debug}` instead of embedding.
    /// When omitted, no agent is injected unless `INTAR_AGENT_BUNDLE` is set at runtime.
    #[serde(default)]
    pub local_agent: Option<bool>,
    #[serde(default)]
    pub vm: HashMap<String, VmConfig>,

    /// Reusable problems grouping tools, manipulation and probes.
    /// Usage inside a VM via `problems = ["name", ...]`.
    #[serde(default, rename = "problem")]
    pub problems: IndexMap<String, Problem>,
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
        assert_eq!(cfg.cpus, 1);
        assert_eq!(cfg.memory, 512);
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

    // Manipulations are now part of problems; top-level manipulation blocks removed.
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct VmConfig {
    /// Number of CPUs for this VM (defaults to 1)
    #[serde(default = "default_cpus")]
    pub cpus: u8,

    /// Memory in MB for this VM (defaults to 512)
    #[serde(default = "default_memory")]
    pub memory: u32,

    /// Custom SSH authorized keys for this specific VM (optional)
    #[serde(default)]
    pub ssh_authorized_keys: Vec<String>,

    /// Custom network configuration for this VM (optional)
    #[serde(default)]
    pub network: Option<NetworkConfig>,

    /// References to reusable problem definitions by label.
    /// Problems group tools, manipulation and probes.
    #[serde(default)]
    pub problems: Vec<String>,
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

/// Packages and utilities needed by a problem.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct Tools {
    /// Packages to install.
    #[serde(default)]
    pub packages: Vec<String>,
}

/// Comparison operator for probe evaluation.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Comparator {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

impl Default for Comparator {
    fn default() -> Self {
        Self::Eq
    }
}

/// A single Prometheus metric assertion.
#[derive(Debug, Deserialize, Clone)]
pub struct ProbeSpec {
    /// Metric name to evaluate.
    pub metric: String,
    /// Optional label filters (subset match).
    #[serde(default)]
    pub labels: IndexMap<String, String>,
    /// Comparator to apply against the observed value.
    #[serde(default)]
    pub op: Comparator,
    /// Target value to compare against.
    pub value: f64,
    /// Optional timeout per probe in milliseconds (defaults provided at runtime).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Optional polling interval in milliseconds (defaults provided at runtime).
    #[serde(default)]
    pub interval_ms: Option<u64>,
}

/// Reusable problem definition.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct Problem {
    /// Short description of the problem.
    #[serde(default)]
    pub description: String,
    /// Tools (packages) to install.
    #[serde(default)]
    pub tools: Tools,
    /// Manipulation to apply (packages + one script).
    #[serde(default)]
    pub manipulation: Manipulation,
    /// Probes to be evaluated for VMs referencing this problem.
    /// Declared as labeled blocks: `probe "name" { ... }`.
    #[serde(default, rename = "probe")]
    pub probes: IndexMap<String, ProbeSpec>,
}

// Empty ref type removed: we now reference by string labels for simplicity

// Default values
const fn default_cpus() -> u8 {
    1
}

const fn default_memory() -> u32 {
    512
}

const fn default_route_metric() -> u32 {
    100
}
