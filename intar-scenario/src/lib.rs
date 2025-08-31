use rust_embed::RustEmbed;

pub mod models;
pub use models::*;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(RustEmbed)]
#[folder = "../scenarios/"]
pub struct EmbeddedScenarios;

pub fn read_embedded_scenario(filename: &str) -> Result<Scenario> {
    match EmbeddedScenarios::get(filename) {
        Some(file) => {
            let content = std::str::from_utf8(file.data.as_ref())?;
            let scenario: Scenario = hcl::from_str(content)?;
            Ok(scenario)
        }
        None => Err(format!("Embedded scenario file '{}' not found", filename).into()),
    }
}

pub fn list_embedded_scenarios() -> Vec<String> {
    EmbeddedScenarios::iter()
        .map(|path| path.to_string())
        .collect()
}
