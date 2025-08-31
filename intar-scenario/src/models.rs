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
pub struct VmConfig {}
