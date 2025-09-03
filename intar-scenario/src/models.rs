use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct Scenario {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub image: String,
    #[serde(default)]
    pub vm: HashMap<String, VmConfig>,
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
fn default_cpus() -> u8 {
    2
}

fn default_memory() -> u32 {
    2048
}

fn default_route_metric() -> u32 {
    100
}
