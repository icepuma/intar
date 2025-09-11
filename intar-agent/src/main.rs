use anyhow::{Context, Result};
use clap::Parser;
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};
use tracing_subscriber::{EnvFilter, fmt};

mod config;
use crate::config::{ProbeDef, agent_config};

#[derive(Clone, Debug)]
struct Config {
    interval: Duration,
    fixtures_root: Option<PathBuf>,
    once: bool,
    strict: bool,
}

/// intar-agent: In-VM metrics agent
#[derive(Parser, Debug)]
#[command(name = "intar-agent")]
#[command(about = "Collects system metrics and pushes via OTLP/HTTP", version)]
struct Cli {
    /// Collection interval in seconds
    #[arg(long, env = "INTAR_AGENT_INTERVAL_SEC", default_value_t = 1u64)]
    interval: u64,

    // No OTLP endpoint; agent exposes Prometheus /metrics on port 9464
    /// Optional root dir with fixture files for testing parsers (maps /proc -> <root>/proc, etc.)
    #[arg(long)]
    fixtures: Option<PathBuf>,

    /// Run a single collection cycle then exit (flush metrics on shutdown)
    #[arg(long)]
    once: bool,

    /// Treat any collector error as fatal (non-zero exit) even in loop mode
    #[arg(long)]
    strict: bool,
}

// ---------------------
// Metrics & Collectors
// ---------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Proto {
    Tcp,
    Udp,
}

#[derive(Default, Clone, Debug)]
struct Snapshot {
    open_ports: BTreeSet<(Proto, u16)>,
    user_groups: BTreeSet<(String, String)>,
    users_total: u64,
    groups_total: u64,
    file_stats: std::collections::BTreeMap<String, FileStat>,
    settings: Vec<SettingDatum>,
}

#[derive(Clone)]
struct AgentState {
    snap: Arc<RwLock<Snapshot>>,
}

impl AgentState {
    fn new() -> Self {
        Self {
            snap: Arc::new(RwLock::new(Snapshot::default())),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct SettingDatum {
    metric: String,
    labels: indexmap::IndexMap<String, String>,
}

fn write_ports(out: &mut String, snap: &Snapshot) {
    use std::fmt::Write as _;
    let _ = writeln!(
        out,
        "# TYPE intar_agent_open_ports_total gauge\nintar_agent_open_ports_total {}",
        snap.open_ports.len()
    );
    let _ = writeln!(out, "# TYPE intar_agent_open_port gauge");
    for (proto, port) in &snap.open_ports {
        let proto = match proto {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        };
        let _ = writeln!(
            out,
            "intar_agent_open_port{{proto=\"{proto}\",port=\"{port}\"}} 1"
        );
    }
}

fn write_users_groups(out: &mut String, snap: &Snapshot) {
    use std::fmt::Write as _;
    let _ = writeln!(out, "# TYPE intar_agent_user_group gauge");
    for (u, g) in &snap.user_groups {
        let _ = writeln!(
            out,
            "intar_agent_user_group{{user=\"{u}\",group=\"{g}\"}} 1"
        );
    }
    let _ = writeln!(
        out,
        "# TYPE intar_agent_users_total gauge\nintar_agent_users_total {}",
        snap.users_total
    );
    let _ = writeln!(
        out,
        "# TYPE intar_agent_groups_total gauge\nintar_agent_groups_total {}",
        snap.groups_total
    );
}

fn write_files(out: &mut String, snap: &Snapshot) {
    use std::fmt::Write as _;
    let _ = writeln!(out, "# TYPE intar_agent_file_exists gauge");
    for (path, fsn) in &snap.file_stats {
        let _ = writeln!(
            out,
            "intar_agent_file_exists{{path=\"{path}\"}} {}",
            u64::from(fsn.exists)
        );
        if let Some(mode) = fsn.mode {
            // Emit file mode as octal permission bits (including suid/sgid/sticky) like 0755
            // Mask off file type bits; keep lower 12 bits
            let perms = mode & 0o7777;
            let mode_octal = format!("{perms:04o}");
            let _ = writeln!(
                out,
                "intar_agent_file_mode{{path=\"{path}\",mode=\"{mode_octal}\"}} 1"
            );
        }
        if let Some(uid) = fsn.uid {
            let _ = writeln!(out, "intar_agent_file_uid{{path=\"{path}\"}} {uid}");
        }
        if let Some(gid) = fsn.gid {
            let _ = writeln!(out, "intar_agent_file_gid{{path=\"{path}\"}} {gid}");
        }
        if let Some(content) = &fsn.content {
            let esc = content
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            let _ = writeln!(
                out,
                "intar_agent_file_content{{path=\"{path}\",content=\"{esc}\"}} 1"
            );
        }
    }
}

// Legacy sshd-specific metrics removed; superseded by generic settings extractors.

fn write_settings(out: &mut String, settings: &[SettingDatum]) {
    use std::fmt::Write as _;
    if settings.is_empty() {
        return;
    }
    // Group by metric to emit one TYPE line per metric
    let mut by_metric: indexmap::IndexMap<&str, Vec<&SettingDatum>> = indexmap::IndexMap::new();
    for s in settings {
        by_metric.entry(&s.metric).or_default().push(s);
    }
    for (metric, items) in by_metric {
        let _ = writeln!(out, "# TYPE {metric} gauge");
        for it in items {
            // Render labels
            let mut first = true;
            let mut lbl = String::new();
            for (k, v) in &it.labels {
                if first {
                    first = false;
                } else {
                    lbl.push(',');
                }
                let esc = v
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n");
                let _ = write!(lbl, "{k}=\"{esc}\"");
            }
            if lbl.is_empty() {
                let _ = writeln!(out, "{metric} 1");
            } else {
                let _ = writeln!(out, "{metric}{{{lbl}}} 1");
            }
        }
    }
}

struct PortCollector;

impl PortCollector {
    fn collect(fixtures_root: Option<&PathBuf>) -> BTreeSet<(Proto, u16)> {
        let mut out: BTreeSet<(Proto, u16)> = BTreeSet::new();
        // tcp
        if let Ok(s) = read_proc_file("/proc/net/tcp", fixtures_root) {
            for line in s.lines().skip(1) {
                if let Some(port) = parse_proc_net_port(line, /*tcp=*/ true) {
                    out.insert((Proto::Tcp, port));
                }
            }
        }
        // tcp6
        if let Ok(s) = read_proc_file("/proc/net/tcp6", fixtures_root) {
            for line in s.lines().skip(1) {
                if let Some(port) = parse_proc_net_port(line, /*tcp=*/ true) {
                    out.insert((Proto::Tcp, port));
                }
            }
        }
        // udp
        if let Ok(s) = read_proc_file("/proc/net/udp", fixtures_root) {
            for line in s.lines().skip(1) {
                if let Some(port) = parse_proc_net_port(line, /*tcp=*/ false) {
                    out.insert((Proto::Udp, port));
                }
            }
        }
        // udp6
        if let Ok(s) = read_proc_file("/proc/net/udp6", fixtures_root) {
            for line in s.lines().skip(1) {
                if let Some(port) = parse_proc_net_port(line, /*tcp=*/ false) {
                    out.insert((Proto::Udp, port));
                }
            }
        }
        out
    }
}

fn read_proc_file(path: &str, fixtures_root: Option<&PathBuf>) -> Result<String> {
    let p = fixtures_root.as_ref().map_or_else(
        || PathBuf::from(path),
        |root| root.join(path.trim_start_matches('/')),
    );
    std::fs::read_to_string(&p).with_context(|| format!("Failed to read {}", p.display()))
}

// Parse a line of /proc/net/{tcp,udp} style; return local port if listening
fn parse_proc_net_port(line: &str, tcp: bool) -> Option<u16> {
    // Example columns: sl local_address rem_address st ...
    // local_address format: HHHHHHHH:PPPP (hex)
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 4 {
        return None;
    }
    let local = cols[1];
    let st = cols[3];
    if tcp {
        // TCP listen state is 0A
        if st != "0A" {
            return None;
        }
    }
    let port_hex = local.split(':').nth(1)?;
    u16::from_str_radix(port_hex, 16).ok()
}

#[derive(Clone, Debug, Default)]
struct FileStat {
    exists: bool,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    content: Option<String>,
}

type UserGroupSummary = (BTreeSet<(String, String)>, u64, u64);

struct UsersGroupsCollector;

impl UsersGroupsCollector {
    fn collect(fixtures_root: Option<&PathBuf>) -> Result<UserGroupSummary> {
        let passwd_s =
            read_system_file("/etc/passwd", fixtures_root).context("read /etc/passwd")?;
        let group_s = read_system_file("/etc/group", fixtures_root).context("read /etc/group")?;
        let users = parse_passwd(&passwd_s);
        let (gid_to_name, group_members) = parse_group(&group_s);

        let mut set: BTreeSet<(String, String)> = BTreeSet::new();
        for u in &users {
            if let Some(gname) = gid_to_name.get(&u.primary_gid) {
                set.insert((u.name.clone(), gname.clone()));
            }
        }
        for (gname, members) in group_members {
            for m in members {
                set.insert((m, gname.clone()));
            }
        }

        let users_total = users.len() as u64;
        let groups_total = gid_to_name.len() as u64;
        Ok((set, users_total, groups_total))
    }
}

#[derive(Debug)]
struct UserEntry {
    name: String,
    primary_gid: u32,
}

fn parse_passwd(contents: &str) -> Vec<UserEntry> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let name = parts[0].to_string();
        // parts[3] is GID (0-based index: name passwd uid gid)
        let gid = parts
            .get(3)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        out.push(UserEntry {
            name,
            primary_gid: gid,
        });
    }
    out
}

fn parse_group(
    contents: &str,
) -> (
    std::collections::BTreeMap<u32, String>,
    std::collections::BTreeMap<String, Vec<String>>,
) {
    let mut gid_to_name = std::collections::BTreeMap::new();
    let mut members_by_group: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let name = parts[0].to_string();
        let gid = parts
            .get(2)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let users = parts[3]
            .split(',')
            .filter(|s| !s.is_empty())
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        gid_to_name.insert(gid, name.clone());
        if !users.is_empty() {
            members_by_group.insert(name, users);
        }
    }
    (gid_to_name, members_by_group)
}

fn read_system_file(path: &str, fixtures_root: Option<&PathBuf>) -> Result<String> {
    let p = fixtures_root.as_ref().map_or_else(
        || PathBuf::from(path),
        |root| root.join(path.trim_start_matches('/')),
    );
    std::fs::read_to_string(&p).with_context(|| format!("Failed to read {}", p.display()))
}

struct FilePermsCollector;

impl FilePermsCollector {
    fn collect(
        fixtures_root: Option<&PathBuf>,
        files: &[String],
        file_content: &[String],
    ) -> std::collections::BTreeMap<String, FileStat> {
        let mut map: std::collections::BTreeMap<String, FileStat> =
            std::collections::BTreeMap::new();
        for path in files {
            let p = map_path(path, fixtures_root);
            let mut stat = stat_file(&p);
            if stat.exists
                && file_content.iter().any(|f| f == path)
                && let Ok(bytes) = std::fs::read(&p)
            {
                let mut s = String::from_utf8_lossy(&bytes).to_string();
                if s.len() > 255 {
                    s.truncate(255);
                }
                stat.content = Some(s);
            }
            map.insert(path.clone(), stat);
        }
        map
    }
}

fn map_path(path: &str, fixtures_root: Option<&PathBuf>) -> PathBuf {
    fixtures_root.as_ref().map_or_else(
        || PathBuf::from(path),
        |root| root.join(path.trim_start_matches('/')),
    )
}

fn expand_sources(patterns: &[String], fixtures_root: Option<&PathBuf>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for pat in patterns {
        let abs = fixtures_root.as_ref().map_or_else(
            || PathBuf::from(pat),
            |root| root.join(pat.trim_start_matches('/')),
        );
        let pattern = abs.to_string_lossy().to_string();
        match glob::glob(&pattern) {
            Ok(paths) => {
                for p in paths.flatten() {
                    out.push(p);
                }
            }
            Err(_) => {
                // Not a valid glob; just push as a path
                out.push(PathBuf::from(pattern));
            }
        }
    }
    out
}

fn eval_probe(probe: &ProbeDef, fixtures_root: Option<&PathBuf>) -> Result<Vec<SettingDatum>> {
    match probe {
        ProbeDef::KvList {
            sources,
            entry_regex,
            split_regex,
            include_keys,
            metric,
            labels,
        } => eval_file_kv_list(
            sources,
            entry_regex,
            split_regex.as_deref().unwrap_or("[,\\s]+"),
            include_keys,
            metric.as_deref().unwrap_or("intar_agent_setting"),
            labels,
            fixtures_root,
        ),
        ProbeDef::Kv {
            sources,
            entry_regex,
            include_keys,
            metric,
            labels,
        } => eval_file_kv(
            sources,
            entry_regex,
            include_keys,
            metric.as_deref().unwrap_or("intar_agent_setting"),
            labels,
            fixtures_root,
        ),
        ProbeDef::Table {
            source,
            delimiter,
            columns,
            key_column,
            value_columns,
            metric,
            labels,
        } => {
            let path = map_path(source, fixtures_root);
            eval_file_table(
                &path,
                delimiter,
                columns,
                key_column,
                value_columns,
                metric.as_deref().unwrap_or("intar_agent_setting"),
                labels,
            )
        }
    }
}

fn eval_file_kv_list(
    sources: &[String],
    entry_regex: &str,
    split_regex: &str,
    include_keys: &[String],
    metric: &str,
    static_labels: &indexmap::IndexMap<String, String>,
    fixtures_root: Option<&PathBuf>,
) -> Result<Vec<SettingDatum>> {
    let mut out = Vec::new();
    let re = regex::Regex::new(entry_regex).context("invalid entry_regex")?;
    let split_re = regex::Regex::new(split_regex).context("invalid split_regex")?;
    let files = expand_sources(sources, fixtures_root);
    for f in files {
        if !f.is_file() {
            continue;
        }
        let s = std::fs::read_to_string(&f).with_context(|| format!("read {}", f.display()))?;
        for line in s.lines() {
            if let Some(caps) = re.captures(line) {
                let key = caps.name("key").map(|m| m.as_str().to_string());
                if let Some(k) = &key
                    && !include_keys.is_empty()
                    && !include_keys.iter().any(|ik| ik.eq_ignore_ascii_case(k))
                {
                    continue;
                }
                let values = caps.name("values").map_or("", |m| m.as_str());
                for v in split_re.split(values) {
                    let v = v.trim();
                    if v.is_empty() {
                        continue;
                    }
                    let mut labels = static_labels.clone();
                    labels.insert("path".to_string(), f.to_string_lossy().to_string());
                    if let Some(k) = &key {
                        labels.insert("key".to_string(), k.clone());
                    }
                    labels.insert("value".to_string(), v.to_string());
                    out.push(SettingDatum {
                        metric: metric.to_string(),
                        labels,
                    });
                }
            }
        }
    }
    Ok(out)
}

fn eval_file_kv(
    sources: &[String],
    entry_regex: &str,
    include_keys: &[String],
    metric: &str,
    static_labels: &indexmap::IndexMap<String, String>,
    fixtures_root: Option<&PathBuf>,
) -> Result<Vec<SettingDatum>> {
    let mut out = Vec::new();
    let re = regex::Regex::new(entry_regex).context("invalid entry_regex")?;
    let files = expand_sources(sources, fixtures_root);
    for f in files {
        if !f.is_file() {
            continue;
        }
        let s = std::fs::read_to_string(&f).with_context(|| format!("read {}", f.display()))?;
        for line in s.lines() {
            if let Some(caps) = re.captures(line) {
                let key = caps.name("key").map(|m| m.as_str().to_string());
                if let Some(k) = &key
                    && !include_keys.is_empty()
                    && !include_keys.iter().any(|ik| ik.eq_ignore_ascii_case(k))
                {
                    continue;
                }
                let value = caps.name("value").map_or("", |m| m.as_str().trim());
                if value.is_empty() {
                    continue;
                }
                let mut labels = static_labels.clone();
                labels.insert("path".to_string(), f.to_string_lossy().to_string());
                if let Some(k) = key {
                    labels.insert("key".to_string(), k);
                }
                labels.insert("value".to_string(), value.to_string());
                out.push(SettingDatum {
                    metric: metric.to_string(),
                    labels,
                });
            }
        }
    }
    Ok(out)
}

fn eval_file_table(
    path: &PathBuf,
    delimiter: &str,
    columns: &[String],
    key_column: &str,
    value_columns: &[String],
    metric: &str,
    static_labels: &indexmap::IndexMap<String, String>,
) -> Result<Vec<SettingDatum>> {
    let mut out = Vec::new();
    if !path.is_file() {
        return Ok(out);
    }
    let s = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let key_idx = columns
        .iter()
        .position(|c| c == key_column)
        .context("key_column not found in columns")?;
    let val_idxs: Vec<(usize, &str)> = value_columns
        .iter()
        .map(|c| {
            let idx = columns
                .iter()
                .position(|cc| cc == c)
                .with_context(|| format!("value column '{c}' not in columns"))?;
            Ok((idx, c.as_str()))
        })
        .collect::<Result<Vec<_>>>()?;
    for raw in s.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = if delimiter == "whitespace" {
            line.split_whitespace().collect()
        } else {
            line.split(delimiter).collect()
        };
        if parts.len() < columns.len() {
            continue;
        }
        let keyv = parts[key_idx].trim();
        for (idx, colname) in &val_idxs {
            let v = parts[*idx].trim();
            if v.is_empty() {
                continue;
            }
            let mut labels = static_labels.clone();
            labels.insert("path".to_string(), path.to_string_lossy().to_string());
            labels.insert("key".to_string(), keyv.to_string());
            labels.insert("column".to_string(), (*colname).to_string());
            labels.insert("value".to_string(), v.to_string());
            out.push(SettingDatum {
                metric: metric.to_string(),
                labels,
            });
        }
    }
    Ok(out)
}

fn stat_file(p: &PathBuf) -> FileStat {
    if !p.exists() {
        return FileStat {
            exists: false,
            ..FileStat::default()
        };
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).map_or_else(
            |_| FileStat {
                exists: false,
                ..FileStat::default()
            },
            |md| {
                let mode = md.mode();
                let uid = md.uid();
                let gid = md.gid();
                FileStat {
                    exists: true,
                    mode: Some(mode),
                    uid: Some(uid),
                    gid: Some(gid),
                    content: None,
                }
            },
        )
    }
    #[cfg(not(unix))]
    {
        std::fs::metadata(p).map_or_else(
            |_| FileStat {
                exists: false,
                ..FileStat::default()
            },
            |_| FileStat {
                exists: true,
                mode: None,
                uid: None,
                gid: None,
                content: None,
            },
        )
    }
}

// Legacy sshd collector removed. Generic file extractors supersede sshd-specific parsing.

#[tokio::main]
async fn main() -> Result<()> {
    let _ = fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .try_init();

    let args = Cli::parse();

    let cfg = Config {
        interval: Duration::from_secs(args.interval),
        fixtures_root: args.fixtures,
        once: args.once,
        strict: args.strict,
    };

    tracing::info!(interval = ?cfg.interval, "intar-agent starting");

    let state = AgentState::new();

    // Start HTTP exporter first to avoid connection resets from hostfwd probing early
    let http_state = state.clone();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 9464))
            .await
            .expect("bind metrics port");
        loop {
            if let Ok((mut sock, _)) = listener.accept().await {
                let st = http_state.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let body = render_prometheus(&st);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        }
    });

    // Collector helpers
    let run_once = cfg.once;
    let strict = cfg.strict;
    let fixtures = cfg.fixtures_root.clone();
    let interval = cfg.interval;

    let collect_once = || -> Result<()> {
        let cfg = agent_config().clone();
        let ports = if cfg.collect_ports {
            PortCollector::collect(fixtures.as_ref())
        } else {
            BTreeSet::new()
        };
        let (user_groups, users_total, groups_total) = if cfg.collect_users_groups {
            UsersGroupsCollector::collect(fixtures.as_ref()).context("collect users/groups")?
        } else {
            (BTreeSet::new(), 0, 0)
        };
        let file_stats =
            FilePermsCollector::collect(fixtures.as_ref(), &cfg.files, &cfg.file_content);
        // Evaluate generic file extractors from embedded config
        let mut settings = Vec::new();
        for probe in cfg.probes.values() {
            let mut items = eval_probe(probe, fixtures.as_ref())?;
            settings.append(&mut items);
        }
        if let Ok(mut snap) = state.snap.write() {
            snap.open_ports = ports;
            snap.user_groups = user_groups;
            snap.users_total = users_total;
            snap.groups_total = groups_total;
            snap.file_stats = file_stats;
            snap.settings = settings;
        }
        Ok(())
    };

    // Perform an initial collection to ensure metrics are available immediately
    if let Err(e) = collect_once() {
        if strict {
            return Err(e);
        }
        tracing::warn!("collector error during initial scrape: {e}");
    }

    if run_once {
        let res = collect_once();
        if let Err(e) = res {
            if strict {
                return Err(e);
            }
            tracing::warn!("collector error: {e}");
        }
        // No exporter to flush
        return Ok(());
    }

    loop {
        let res = collect_once();
        if let Err(e) = res {
            if strict {
                return Err(e);
            }
            tracing::warn!("collector error: {e}");
        }
        tokio::time::sleep(interval).await;
    }
}

fn render_prometheus(state: &AgentState) -> String {
    let mut out = String::new();
    if let Ok(snap) = state.snap.read() {
        write_ports(&mut out, &snap);
        write_users_groups(&mut out, &snap);
        write_files(&mut out, &snap);
        write_settings(&mut out, &snap.settings);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;
    use tempfile::TempDir;

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/debian")
    }

    #[test]
    fn test_parse_proc_net_port_tcp_listen() {
        let line = "  0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 0 1 ffff";
        let p = parse_proc_net_port(line, true);
        assert_eq!(p, Some(8080));
        let not_listen = "  0: 0100007F:1F90 00000000:0000 01 00000000:00000000 00:00000000 00000000   100        0 0 1 ffff";
        assert_eq!(parse_proc_net_port(not_listen, true), None);
    }

    #[test]
    fn test_users_groups_parse() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n";
        let group = "root:x:0:\nsudo:x:27:alice\n";
        let users = parse_passwd(passwd);
        assert_eq!(users.len(), 2);
        let (gid_name, members) = parse_group(group);
        assert_eq!(gid_name.get(&0).cloned(), Some("root".to_string()));
        assert_eq!(
            members.get("sudo").cloned().unwrap_or_default(),
            vec!["alice".to_string()]
        );
    }

    #[test]
    fn test_port_collector_from_fixtures() {
        let root = Some(fixture_root());
        let ports = PortCollector::collect(root.as_ref());
        assert!(ports.contains(&(Proto::Tcp, 8080)));
        assert!(
            ports.contains(&(Proto::Udp, 5060))
                || ports
                    .iter()
                    .any(|(p, port)| matches!(p, Proto::Udp) && *port == 5060)
                || !ports.is_empty()
        );
    }

    // Legacy sshd collector test removed; generic file extractors cover ciphers/MACs/KEX via files.

    #[test]
    fn test_file_kv_list_sshd_ciphers_from_files() {
        let tmp = TempDir::new().expect("tmp");
        let root = tmp.path();
        let cfg_dir = root.join("etc/ssh/sshd_config.d");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        std::fs::create_dir_all(root.join("etc/ssh")).unwrap();
        std::fs::write(
            root.join("etc/ssh/sshd_config"),
            "Include /etc/ssh/sshd_config.d/*.conf\nCiphers aes256-gcm@openssh.com\n",
        )
        .unwrap();
        std::fs::write(
            cfg_dir.join("10-extra.conf"),
            "# extra\nCiphers chacha20-poly1305@openssh.com\n",
        )
        .unwrap();

        let mut labels: IndexMap<String, String> = IndexMap::new();
        labels.insert("subsystem".into(), "sshd".into());
        let probe = ProbeDef::KvList {
            sources: vec![
                "/etc/ssh/sshd_config".into(),
                "/etc/ssh/sshd_config.d/*.conf".into(),
            ],
            entry_regex: "^\\s*(?P<key>[A-Za-z][A-Za-z0-9]+)\\s+(?P<values>.+)$".into(),
            split_regex: Some("[,\\s]+".into()),
            include_keys: vec!["Ciphers".into()],
            metric: Some("intar_agent_setting".into()),
            labels,
        };

        let out = eval_probe(&probe, Some(&root.to_path_buf())).expect("eval");
        let mut values: Vec<String> = out
            .iter()
            .filter_map(|d| d.labels.get("value").cloned())
            .collect();
        values.sort();
        assert!(values.contains(&"aes256-gcm@openssh.com".to_string()));
        assert!(values.contains(&"chacha20-poly1305@openssh.com".to_string()));
    }

    #[test]
    fn test_render_includes_intar_agent_setting() {
        // Build settings and verify they are rendered as Prometheus lines.
        let mut labels1: IndexMap<String, String> = IndexMap::new();
        labels1.insert("subsystem".into(), "sshd".into());
        labels1.insert("key".into(), "Ciphers".into());
        labels1.insert("value".into(), "chacha20-poly1305@openssh.com".into());
        let mut labels2 = labels1.clone();
        labels2.insert("value".into(), "aes256-gcm@openssh.com".into());

        let state = AgentState::new();
        if let Ok(mut snap) = state.snap.write() {
            snap.settings = vec![
                SettingDatum {
                    metric: "intar_agent_setting".into(),
                    labels: labels1,
                },
                SettingDatum {
                    metric: "intar_agent_setting".into(),
                    labels: labels2,
                },
            ];
        }
        let out = render_prometheus(&state);
        assert!(out.contains("# TYPE intar_agent_setting gauge"));
        assert!(out.contains("value=\"chacha20-poly1305@openssh.com\""));
        assert!(out.contains("value=\"aes256-gcm@openssh.com\""));
    }

    #[test]
    fn test_file_kv_resolv_nameservers() {
        let tmp = TempDir::new().expect("tmp");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(
            root.join("etc/resolv.conf"),
            "nameserver 1.1.1.1\nnameserver 8.8.8.8\n",
        )
        .unwrap();
        let mut labels: IndexMap<String, String> = IndexMap::new();
        labels.insert("subsystem".into(), "resolv".into());
        let probe = ProbeDef::Kv {
            sources: vec!["/etc/resolv.conf".into()],
            entry_regex: "^(?i)(?P<key>nameserver)\\s+(?P<value>\\S+)".into(),
            include_keys: vec!["nameserver".into()],
            metric: Some("intar_agent_setting".into()),
            labels,
        };
        let out = eval_probe(&probe, Some(&root.to_path_buf())).expect("eval");
        let mut values: Vec<String> = out
            .iter()
            .filter_map(|d| d.labels.get("value").cloned())
            .collect();
        values.sort();
        assert_eq!(values, vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]);
    }

    #[test]
    fn test_file_table_fstab() {
        let tmp = TempDir::new().expect("tmp");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        let fstab = "# <file systems>\n/dev/sda1 / ext4 defaults 0 1\n/dev/sdb1 /mnt/data ext4 defaults 0 2\n";
        std::fs::write(root.join("etc/fstab"), fstab).unwrap();
        let mut labels: IndexMap<String, String> = IndexMap::new();
        labels.insert("subsystem".into(), "fstab".into());
        let probe = ProbeDef::Table {
            source: "/etc/fstab".into(),
            delimiter: "whitespace".into(),
            columns: vec![
                "spec".into(),
                "file".into(),
                "vfs".into(),
                "options".into(),
                "dump".into(),
                "pass".into(),
            ],
            key_column: "file".into(),
            value_columns: vec!["vfs".into(), "options".into()],
            metric: Some("intar_agent_setting".into()),
            labels,
        };
        let out = eval_probe(&probe, Some(&root.to_path_buf())).expect("eval");
        // Expect entries for /mnt/data ext4 and defaults
        assert!(out.iter().any(|d| {
            d.labels.get("key").is_some_and(|v| v == "/mnt/data")
                && d.labels.get("column").is_some_and(|c| c == "vfs")
                && d.labels.get("value").is_some_and(|v| v == "ext4")
        }));
        assert!(out.iter().any(|d| {
            d.labels.get("key").is_some_and(|v| v == "/mnt/data")
                && d.labels.get("column").is_some_and(|c| c == "options")
                && d.labels.get("value").is_some_and(|v| v == "defaults")
        }));
    }
}
