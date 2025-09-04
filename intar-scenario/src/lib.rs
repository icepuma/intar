use rust_embed::RustEmbed;

pub mod models;
pub use models::*;

#[derive(RustEmbed)]
#[folder = "../scenarios/"]
pub struct EmbeddedScenarios;

/// Reads an embedded scenario by filename.
///
/// # Errors
/// Returns an error if the embedded file is not found or cannot be parsed.
pub fn read_embedded_scenario(filename: &str) -> anyhow::Result<Scenario> {
    match EmbeddedScenarios::get(filename) {
        Some(file) => {
            let content = std::str::from_utf8(file.data.as_ref())?;
            let scenario: Scenario = hcl::from_str(content)?;
            Ok(scenario)
        }
        None => Err(anyhow::anyhow!(
            "Embedded scenario file '{}' not found",
            filename
        )),
    }
}

#[must_use]
pub fn list_embedded_scenarios() -> Vec<String> {
    EmbeddedScenarios::iter()
        .map(|path| path.to_string())
        .collect()
}
