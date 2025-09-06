// Shared constants and helpers for networking

pub const HOSTFWD_BASE_PORT: u16 = 2700; // SSH host forward base port
pub const HUB_PORT_BASE: u16 = 18000; // UDP hub base port per scenario
pub const METADATA_PORT_BASE: u16 = 18500; // HTTP metadata base port per scenario
pub const METRICS_PORT_BASE: u16 = 19000; // Per-VM metrics hostfwd base port

// Deterministic LAN addressing: 172.30.<scenario_id>.(10 + vm_index)
#[must_use]
pub fn lan_ip(scenario_id: u8, vm_index: u8) -> String {
    format!("172.30.{scenario_id}.{}", 10u8.saturating_add(vm_index))
}

#[must_use]
pub fn lan_subnet(scenario_id: u8) -> String {
    format!("172.30.{scenario_id}.0/24")
}

#[must_use]
pub fn hub_port(scenario_id: u8) -> u16 {
    HUB_PORT_BASE + u16::from(scenario_id)
}

#[must_use]
pub fn metadata_port(scenario_id: u8) -> u16 {
    METADATA_PORT_BASE + u16::from(scenario_id)
}

/// Compute a stable host port for per-VM metrics forwarding.
/// Uses `scenario_id` and `vm_index` to avoid collisions across scenarios.
#[must_use]
pub fn metrics_port(scenario_id: u8, vm_index: u8) -> u16 {
    METRICS_PORT_BASE + (u16::from(scenario_id) * 16) + u16::from(vm_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_ip_and_subnet_are_deterministic() {
        assert_eq!(lan_ip(42, 0), "172.30.42.10");
        assert_eq!(lan_ip(42, 1), "172.30.42.11");
        assert_eq!(lan_subnet(42), "172.30.42.0/24");
    }

    #[test]
    fn hub_port_offsets() {
        assert_eq!(hub_port(1), HUB_PORT_BASE + 1);
        assert_eq!(hub_port(200), HUB_PORT_BASE + 200);
    }

    #[test]
    fn metadata_port_offsets() {
        assert_eq!(metadata_port(1), METADATA_PORT_BASE + 1);
        assert_eq!(metadata_port(200), METADATA_PORT_BASE + 200);
    }

    #[test]
    fn metrics_port_offsets() {
        assert_eq!(metrics_port(1, 0), METRICS_PORT_BASE + 16);
        assert_eq!(metrics_port(2, 3), METRICS_PORT_BASE + 32 + 3);
    }
}
