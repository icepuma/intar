use indexmap::IndexMap;
use serde::Deserialize;

/// Agent configuration loaded from embedded HCL (config.hcl).
/// Controls which files are inspected and which have content exported.

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_files")]
    pub files: Vec<String>,
    #[serde(default = "default_file_content")]
    pub file_content: Vec<String>,
    /// Individually configured probes (DSL-style) evaluated by the agent.
    #[serde(default, rename = "probe")]
    pub probes: IndexMap<String, ProbeDef>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            files: default_files(),
            file_content: default_file_content(),
            probes: default_probes(),
        }
    }
}

fn default_files() -> Vec<String> {
    vec![
        "/etc/ssh/sshd_config".to_string(),
        "/etc/sudoers".to_string(),
        "/etc/passwd".to_string(),
        "/etc/shadow".to_string(),
        "/etc/hosts".to_string(),
        "/home/intar/intar.txt".to_string(),
    ]
}

fn default_file_content() -> Vec<String> {
    vec!["/home/intar/intar.txt".to_string()]
}

fn default_probes() -> IndexMap<String, ProbeDef> {
    let mut m = IndexMap::new();
    m.insert(
        "agent_metrics_up".to_string(),
        ProbeDef::OpenPort {
            proto: "tcp".to_string(),
            port: 9464,
        },
    );
    m
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProbeDef {
    OpenPort {
        proto: String,
        port: u16,
    },
    FileExists {
        path: String,
    },
    FileContent {
        path: String,
        #[serde(default)]
        cutoff: Option<usize>,
    },
    FileMode {
        path: String,
    },
    /// Apply a regex to a file's content and expose the first (or specified) capture.
    /// If the regex matches, metric includes a `value` label with the captured text and value 1; otherwise emits 0.
    FileRegex {
        path: String,
        regex: String,
        #[serde(default)]
        group: Option<usize>,
    },
}

/// Embedded config files for the agent.
#[derive(rust_embed::RustEmbed)]
#[folder = "config/"]
struct EmbeddedConfig;

static CONFIG: std::sync::OnceLock<AgentConfig> = std::sync::OnceLock::new();

/// Return a reference to the singleton agent configuration.
/// Falls back to built-in defaults if the embedded file is missing or invalid.
pub fn agent_config() -> &'static AgentConfig {
    CONFIG.get_or_init(|| {
        if let Some(file) = EmbeddedConfig::get("config.hcl")
            && let Ok(s) = std::str::from_utf8(file.data.as_ref())
            && let Ok(cfg) = hcl::from_str::<AgentConfig>(s)
        {
            return cfg;
        }
        AgentConfig::default()
    })
}
