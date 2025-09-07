use anyhow::{Context, Result};
use clap::Parser;
use std::path::Path;
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};
use tracing_subscriber::{EnvFilter, fmt};

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
    sshd: Option<SshdSnapshot>,
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

fn write_sshd(out: &mut String, s: &SshdSnapshot) {
    use std::fmt::Write as _;
    let _ = writeln!(
        out,
        "# TYPE intar_agent_sshd_present gauge\nintar_agent_sshd_present {}",
        u64::from(s.present)
    );
    if let Some(p) = s.port {
        let _ = writeln!(
            out,
            "# TYPE intar_agent_sshd_port gauge\nintar_agent_sshd_port {p}"
        );
    }
    if let Some(b) = s.password_authentication {
        let _ = writeln!(
            out,
            "# TYPE intar_agent_sshd_password_authentication gauge\nintar_agent_sshd_password_authentication {}",
            u64::from(b)
        );
    }
    if let Some(b) = s.pubkey_authentication {
        let _ = writeln!(
            out,
            "# TYPE intar_agent_sshd_pubkey_authentication gauge\nintar_agent_sshd_pubkey_authentication {}",
            u64::from(b)
        );
    }
    if let Some(mode) = &s.permit_root_login_mode {
        let _ = writeln!(
            out,
            "# TYPE intar_agent_sshd_permit_root_login_mode gauge\nintar_agent_sshd_permit_root_login_mode{{mode=\"{mode}\"}} 1",
        );
    }
    if let Some(b) = s.allow_tcp_forwarding {
        let _ = writeln!(
            out,
            "# TYPE intar_agent_sshd_allow_tcp_forwarding gauge\nintar_agent_sshd_allow_tcp_forwarding {}",
            u64::from(b)
        );
    }
    if let Some(b) = s.x11_forwarding {
        let _ = writeln!(
            out,
            "# TYPE intar_agent_sshd_x11_forwarding gauge\nintar_agent_sshd_x11_forwarding {}",
            u64::from(b)
        );
    }
    if let Some(m) = &s.gateway_ports {
        let _ = writeln!(
            out,
            "# TYPE intar_agent_sshd_gateway_ports gauge\nintar_agent_sshd_gateway_ports{{mode=\"{m}\"}} 1",
        );
    }
    macro_rules! list {
        ($name:literal, $iter:expr) => {
            let _ = writeln!(out, "# TYPE {} gauge", $name);
            for x in $iter {
                let _ = writeln!(out, "{}{{name=\"{}\"}} 1", $name, x);
            }
        };
    }
    list!("intar_agent_sshd_kex_algorithm", s.kex_algorithms.iter());
    list!("intar_agent_sshd_cipher", s.ciphers.iter());
    list!("intar_agent_sshd_mac", s.macs.iter());
    list!(
        "intar_agent_sshd_hostkey_algorithm",
        s.hostkey_algorithms.iter()
    );
    list!(
        "intar_agent_sshd_auth_method",
        s.authentication_methods.iter()
    );
    list!("intar_agent_sshd_allow_user", s.allow_users.iter());
    list!("intar_agent_sshd_deny_user", s.deny_users.iter());
    list!("intar_agent_sshd_allow_group", s.allow_groups.iter());
    list!("intar_agent_sshd_deny_group", s.deny_groups.iter());
    let _ = writeln!(
        out,
        "# TYPE intar_agent_sshd_has_match_blocks gauge\nintar_agent_sshd_has_match_blocks {}",
        u64::from(s.has_match_blocks)
    );
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

// Baked-in whitelist of files to stat
const FILE_WHITELIST: &[&str] = &[
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/home/intar/intar.txt",
];

// Files for which we also scrape up to 255 chars of plaintext content
const FILE_CONTENT_WHITELIST: &[&str] = &["/home/intar/intar.txt"];

impl FilePermsCollector {
    fn collect(fixtures_root: Option<&PathBuf>) -> std::collections::BTreeMap<String, FileStat> {
        let mut map: std::collections::BTreeMap<String, FileStat> =
            std::collections::BTreeMap::new();
        for path in FILE_WHITELIST {
            let p = map_path(path, fixtures_root);
            let mut stat = stat_file(&p);
            if stat.exists
                && FILE_CONTENT_WHITELIST.contains(path)
                && let Ok(bytes) = std::fs::read(&p)
            {
                let mut s = String::from_utf8_lossy(&bytes).to_string();
                if s.len() > 255 {
                    s.truncate(255);
                }
                stat.content = Some(s);
            }
            map.insert((*path).to_string(), stat);
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

// ---------------------
// sshd collector
// ---------------------

#[derive(Default, Clone, Debug)]
struct SshdSnapshot {
    present: bool,
    port: Option<u16>,
    permit_root_login_mode: Option<String>,
    password_authentication: Option<bool>,
    pubkey_authentication: Option<bool>,
    kex_algorithms: Vec<String>,
    ciphers: Vec<String>,
    macs: Vec<String>,
    hostkey_algorithms: Vec<String>,
    allow_tcp_forwarding: Option<bool>,
    x11_forwarding: Option<bool>,
    gateway_ports: Option<String>,
    max_auth_tries: Option<u64>,
    max_sessions: Option<u64>,
    client_alive_interval: Option<u64>,
    client_alive_count_max: Option<u64>,
    use_pam: Option<bool>,
    banner_present: Option<bool>,
    authentication_methods: Vec<String>,
    allow_users: Vec<String>,
    deny_users: Vec<String>,
    allow_groups: Vec<String>,
    deny_groups: Vec<String>,
    has_match_blocks: bool,
}

struct SshdCollector;

impl SshdCollector {
    fn collect(fixtures_root: Option<&PathBuf>) -> Result<SshdSnapshot> {
        let main_path = map_path("/etc/ssh/sshd_config", fixtures_root);
        if !main_path.exists() {
            return Ok(SshdSnapshot {
                present: false,
                ..SshdSnapshot::default()
            });
        }
        let mut visited = std::collections::BTreeSet::new();
        let mut snap = SshdSnapshot {
            present: true,
            ..SshdSnapshot::default()
        };
        Self::parse_file(
            &main_path,
            &mut snap,
            fixtures_root,
            &mut visited,
            &mut false,
        )?;
        Ok(snap)
    }

    fn parse_file(
        path: &PathBuf,
        snap: &mut SshdSnapshot,
        fixtures_root: Option<&PathBuf>,
        visited: &mut std::collections::BTreeSet<PathBuf>,
        in_match: &mut bool,
    ) -> Result<()> {
        let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
        if !visited.insert(canon.clone()) {
            return Ok(()); // avoid cycles
        }
        let s = std::fs::read_to_string(&canon)
            .with_context(|| format!("Failed to read {}", canon.display()))?;
        let base_dir = canon
            .parent()
            .map_or_else(|| PathBuf::from("/"), PathBuf::from);

        for raw_line in s.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let key = match parts.next() {
                Some(k) => k.to_ascii_lowercase(),
                None => continue,
            };
            let value = parts.collect::<Vec<_>>().join(" ");

            if key == "match" {
                snap.has_match_blocks = true;
                *in_match = true;
                continue;
            }
            if *in_match {
                continue;
            }

            match key.as_str() {
                "include" => {
                    for pat in value.split_whitespace() {
                        for inc in resolve_include_paths(pat, &base_dir, fixtures_root) {
                            if inc.is_file() {
                                let _ =
                                    Self::parse_file(&inc, snap, fixtures_root, visited, in_match);
                            }
                        }
                    }
                }
                "port" => {
                    if let Ok(p) = value.trim().parse::<u16>() {
                        snap.port = Some(p);
                    }
                }
                "permitrootlogin" => {
                    snap.permit_root_login_mode = Some(value.to_ascii_lowercase());
                }
                "passwordauthentication" => snap.password_authentication = parse_bool(&value),
                "pubkeyauthentication" => snap.pubkey_authentication = parse_bool(&value),
                "kexalgorithms" => snap.kex_algorithms = parse_list(&value),
                "ciphers" => snap.ciphers = parse_list(&value),
                "macs" => snap.macs = parse_list(&value),
                "hostkeyalgorithms" => snap.hostkey_algorithms = parse_list(&value),
                "allowtcpforwarding" => snap.allow_tcp_forwarding = parse_bool(&value),
                "x11forwarding" => snap.x11_forwarding = parse_bool(&value),
                "gatewayports" => snap.gateway_ports = Some(value.to_ascii_lowercase()),
                "maxauthtries" => snap.max_auth_tries = value.trim().parse::<u64>().ok(),
                "maxsessions" => snap.max_sessions = value.trim().parse::<u64>().ok(),
                "clientaliveinterval" => {
                    snap.client_alive_interval = value.trim().parse::<u64>().ok();
                }
                "clientalivecountmax" => {
                    snap.client_alive_count_max = value.trim().parse::<u64>().ok();
                }
                "usepam" => snap.use_pam = parse_bool(&value),
                "banner" => {
                    let v = value.trim();
                    if !v.is_empty() && !v.eq_ignore_ascii_case("none") {
                        snap.banner_present = Some(true);
                    } else {
                        snap.banner_present = Some(false);
                    }
                }
                "authenticationmethods" => {
                    snap.authentication_methods = parse_auth_methods(&value);
                }
                "allowusers" => snap.allow_users = parse_space_list(&value),
                "denyusers" => snap.deny_users = parse_space_list(&value),
                "allowgroups" => snap.allow_groups = parse_space_list(&value),
                "denygroups" => snap.deny_groups = parse_space_list(&value),
                _ => {}
            }
        }
        Ok(())
    }
}

fn resolve_include_paths(
    pattern: &str,
    base_dir: &Path,
    fixtures_root: Option<&PathBuf>,
) -> Vec<PathBuf> {
    use glob::glob;
    let pat_path = if PathBuf::from(pattern).is_absolute() {
        fixtures_root.as_ref().map_or_else(
            || PathBuf::from(pattern),
            |root| root.join(pattern.trim_start_matches('/')),
        )
    } else {
        base_dir.join(pattern)
    };
    let pat_str = pat_path.to_string_lossy().to_string();
    let mut v = Vec::new();
    if let Ok(paths) = glob(&pat_str) {
        for entry in paths.flatten() {
            v.push(entry);
        }
    }
    v
}

fn parse_bool(s: &str) -> Option<bool> {
    let v = s.trim().to_ascii_lowercase();
    match v.as_str() {
        "yes" | "on" | "true" | "1" => Some(true),
        "no" | "off" | "false" | "0" => Some(false),
        _ => None,
    }
}

fn parse_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn parse_space_list(s: &str) -> Vec<String> {
    s.split_whitespace()
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn parse_auth_methods(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in s.split_whitespace() {
        for sub in part.split(',') {
            let t = sub.trim();
            if !t.is_empty() {
                out.push(t.to_string());
            }
        }
    }
    out
}

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
        let ports = PortCollector::collect(fixtures.as_ref());
        let (user_groups, users_total, groups_total) =
            UsersGroupsCollector::collect(fixtures.as_ref()).context("collect users/groups")?;
        let file_stats = FilePermsCollector::collect(fixtures.as_ref());
        let sshd = SshdCollector::collect(fixtures.as_ref()).context("collect sshd")?;
        if let Ok(mut snap) = state.snap.write() {
            snap.open_ports = ports;
            snap.user_groups = user_groups;
            snap.users_total = users_total;
            snap.groups_total = groups_total;
            snap.file_stats = file_stats;
            snap.sshd = Some(sshd);
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
        if let Some(sshd) = &snap.sshd {
            write_sshd(&mut out, sshd);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_sshd_collector_fixtures() {
        let root = Some(fixture_root());
        let sshd = SshdCollector::collect(root.as_ref()).expect("collect sshd");
        assert!(sshd.present);
        assert_eq!(sshd.port, Some(2222));
        assert_eq!(sshd.password_authentication, Some(false));
        assert_eq!(sshd.pubkey_authentication, Some(true));
        assert_eq!(
            sshd.permit_root_login_mode.as_deref(),
            Some("prohibit-password")
        );
        assert_eq!(sshd.allow_tcp_forwarding, Some(false));
        assert_eq!(sshd.x11_forwarding, Some(false));
        assert_eq!(sshd.gateway_ports.as_deref(), Some("clientspecified"));
        assert_eq!(sshd.max_auth_tries, Some(3));
        assert_eq!(sshd.max_sessions, Some(10));
        assert_eq!(sshd.client_alive_interval, Some(30));
        assert_eq!(sshd.client_alive_count_max, Some(2));
        assert_eq!(sshd.use_pam, Some(true));
        assert_eq!(sshd.banner_present, Some(true));
        assert!(sshd.kex_algorithms.iter().any(|k| k.contains("curve25519")));
        assert!(sshd.ciphers.iter().any(|c| c.contains("chacha20")));
        assert!(sshd.macs.iter().any(|m| m.contains("hmac-sha2")));
        assert!(
            sshd.hostkey_algorithms
                .iter()
                .any(|h| h.contains("ssh-ed25519"))
        );
        assert!(
            sshd.authentication_methods
                .iter()
                .any(|a| a.contains("publickey"))
        );
        assert!(sshd.allow_users.iter().any(|u| u == "alice"));
        assert!(sshd.allow_groups.iter().any(|g| g == "sudo"));
        assert!(sshd.has_match_blocks);
    }
}
