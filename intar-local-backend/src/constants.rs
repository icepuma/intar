// Shared constants and helpers for networking

pub const HOSTFWD_BASE_PORT: u16 = 2700; // SSH host forward base port
pub const HUB_PORT_BASE: u16 = 18000; // UDP hub base port per scenario

// Deterministic LAN addressing: 172.30.<scenario_id>.(10 + vm_index)
pub fn lan_ip(scenario_id: u8, vm_index: u8) -> String {
    format!("172.30.{}.{}", scenario_id, 10u8.saturating_add(vm_index))
}

pub fn lan_subnet(scenario_id: u8) -> String {
    format!("172.30.{}.0/24", scenario_id)
}

pub fn hub_port(scenario_id: u8) -> u16 {
    HUB_PORT_BASE + scenario_id as u16
}
