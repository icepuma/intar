use anyhow::{Context, Result};
use indexmap::IndexMap;
use std::sync::OnceLock;

/// One parsed Prometheus sample.
#[derive(Debug, Clone)]
pub struct Sample {
    pub name: String,
    pub labels: IndexMap<String, String>,
    pub value: f64,
}

/// Fetch metrics text from a VM-local forwarded port.
static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn metrics_client() -> Result<&'static reqwest::Client> {
    let timeout_ms: u64 = std::env::var("INTAR_METRICS_SCRAPE_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2_000);
    if let Some(c) = CLIENT.get() {
        return Ok(c);
    }
    let built = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(timeout_ms))
        .build()?;
    let _ = CLIENT.set(built);
    Ok(CLIENT.get().expect("metrics client initialized"))
}

pub async fn fetch_metrics_text(url: &str) -> Result<String> {
    let client = metrics_client()?;
    let resp = client
        .get(url)
        .header("user-agent", "intar-metrics-scraper/0.1")
        .send()
        .await
        .with_context(|| format!("fetch metrics from {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {status} for {url}");
    }
    let body = resp.text().await?;
    Ok(body)
}

/// Minimal Prometheus text parser supporting `name{labels} value` lines.
pub fn parse_prometheus_text(text: &str) -> Vec<Sample> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Split into metric+labels and value
        let mut parts = line.rsplitn(2, char::is_whitespace);
        let Some(val_str) = parts.next() else {
            continue;
        };
        let Some(left) = parts.next() else { continue };
        let Ok(value) = val_str.parse::<f64>() else {
            continue;
        };

        // Parse name and optional label block
        let (name, labels) = if let Some((n, rest)) = left.split_once('{') {
            let label_part = rest.strip_suffix('}').unwrap_or(rest);
            let labels = parse_labels(label_part);
            (n.to_string(), labels)
        } else {
            (left.to_string(), IndexMap::new())
        };
        out.push(Sample {
            name,
            labels,
            value,
        });
    }
    out
}

fn parse_labels(s: &str) -> IndexMap<String, String> {
    let mut map = IndexMap::new();
    let mut i = 0usize;
    let b = s.as_bytes();
    while i < b.len() {
        // skip whitespace and commas
        while i < b.len() && (b[i] as char).is_whitespace() || (i < b.len() && b[i] == b',') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        // key
        let start_k = i;
        while i < b.len() && b[i] != b'=' {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let key = s[start_k..i].trim().to_string();
        i += 1; // skip '='
        if i >= b.len() || b[i] != b'"' {
            break;
        }
        i += 1; // skip opening quote
        let mut val = String::new();
        while i < b.len() {
            let c = b[i] as char;
            if c == '"' {
                i += 1; // consume closing quote
                break;
            }
            if c == '\\' && i + 1 < b.len() {
                let nxt = b[i + 1] as char;
                match nxt {
                    'n' => val.push('\n'),
                    '\\' => val.push('\\'),
                    '"' => val.push('"'),
                    _ => val.push(nxt),
                }
                i += 2;
            } else {
                val.push(c);
                i += 1;
            }
        }
        map.insert(key, val);
        // skip trailing spaces/commas before next label
        while i < b.len() && ((b[i] as char).is_whitespace() || b[i] == b',') {
            i += 1;
        }
    }
    map
}

/// Subset label match helper.
pub fn labels_match(sample: &IndexMap<String, String>, filter: &IndexMap<String, String>) -> bool {
    for (k, v) in filter {
        match sample.get(k) {
            Some(sv) if sv == v => {}
            _ => return false,
        }
    }
    true
}
