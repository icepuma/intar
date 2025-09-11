use indexmap::IndexMap;
use serde::Deserialize;

/// Agent configuration loaded from embedded HCL (config.hcl).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AgentConfig {
    /// Files to stat for existence/permissions/ownership metrics.
    #[serde(default)]
    pub files: Vec<String>,
    /// Files whose (short) content should be exposed.
    #[serde(default)]
    pub file_content: Vec<String>,
    /// Enable collection of open TCP/UDP ports from /proc.
    #[serde(default = "default_true")]
    pub collect_ports: bool,
    /// Enable collection of users/groups and relationships.
    #[serde(default = "default_true")]
    pub collect_users_groups: bool,
    /// Individually configured probes (DSL-style) evaluated by the agent.
    #[serde(default, rename = "probe")]
    pub probes: IndexMap<String, ProbeDef>,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProbeDef {
    // Structured extractors.
    /// Extract multi-value settings from one or more files by capturing a key and a list of values.
    /// The `entry_regex` must define named captures `key` and `values`. Values are split by `split_regex` (default: /[,\s]+/).
    /// Each emitted item becomes one metric with labels merged from `labels` and dynamic labels: path, key, value.
    KvList {
        /// One or more files/globs to parse (evaluated in order)
        sources: Vec<String>,
        /// Regex with named captures `key` and `values`
        entry_regex: String,
        /// Optional split regex (default: "[,\\s]+")
        #[serde(default)]
        split_regex: Option<String>,
        /// Optional filter for keys; if empty, all keys match
        #[serde(default)]
        include_keys: Vec<String>,
        /// Optional metric name override (default: `intar_agent_setting`)
        #[serde(default)]
        metric: Option<String>,
        /// Static labels to attach to each emitted metric
        #[serde(default)]
        labels: indexmap::IndexMap<String, String>,
    },
    /// Extract single-value or repeated key/value pairs across files.
    /// The `entry_regex` must define named captures `key` and `value`.
    Kv {
        sources: Vec<String>,
        entry_regex: String,
        #[serde(default)]
        include_keys: Vec<String>,
        #[serde(default)]
        metric: Option<String>,
        #[serde(default)]
        labels: indexmap::IndexMap<String, String>,
    },
    /// Parse colon/whitespace-delimited tables (e.g., passwd, fstab).
    /// Emits one metric per row per listed value column with labels: path, key=<`key_column`>, column=<which>, value=<cell>.
    Table {
        source: String,
        /// "whitespace" or a literal delimiter string such as ":"
        delimiter: String,
        /// Column names in order
        columns: Vec<String>,
        /// Name of the column to use as the logical key
        key_column: String,
        /// One or more column names to emit as values
        value_columns: Vec<String>,
        #[serde(default)]
        metric: Option<String>,
        #[serde(default)]
        labels: indexmap::IndexMap<String, String>,
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
