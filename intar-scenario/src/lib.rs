use rust_embed::RustEmbed;

pub mod models;
pub use models::*;

/// Embedded HCL scenarios bundled at compile time from the `scenarios/` folder.
#[derive(RustEmbed)]
#[folder = "../scenarios/"]
pub struct EmbeddedScenarios;

/// Read an embedded scenario by filename and parse it into `Scenario`.
///
/// # Errors
/// Returns an error if the embedded file is not found or HCL parsing fails.
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

/// List all embedded scenarios by path name.
#[must_use]
pub fn list_embedded_scenarios() -> Vec<String> {
    EmbeddedScenarios::iter()
        .map(|path| path.to_string())
        .collect()
}
