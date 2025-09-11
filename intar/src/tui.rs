//! Minimal TUI for scenario runs with cooperative shutdown.
//!
//! The TUI enters the alternate screen and, when key handling is enabled,
//! enables terminal raw mode to read key presses. It listens for Ctrl+C as an
//! in-TUI quit signal and restores the terminal state cooperatively (showing
//! the cursor, disabling raw mode, then leaving the alternate screen).
//!
//! Set the `INTAR_TUI_DISABLE_KEYS=1` environment variable to disable key
//! handling. In that mode the TUI does not enable raw mode and you should use
//! OS signals (Ctrl+C) to stop the run.

use crate::probes::{ProbeState, ProbesState};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use intar::IntarDirs;
use ratatui::prelude::{
    Alignment, Color, Constraint, Direction, Layout, Line, Modifier, Rect, Span, Style,
};
use ratatui::widgets::block::Padding;
use ratatui::widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::stdout;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::sync::broadcast;

// (tiles view removed; now using a table view for VMs)

/// High-level step state for the boot sequence.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    Pending,
    Running,
    Done,
}

/// VM startup phase for table rendering.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VmPhase {
    Pending,
    Starting,
    SshWait,
    Ready,
}

/// Shared UI state snapshot rendered by the TUI.
pub struct UiState {
    pub scenario_name: String,
    pub scenario_description: String,
    pub total_vms: usize,
    pub run_started: Instant,
    pub run_completed: Option<Instant>,
    pub quote: Option<(String, String)>, // (text, person)
    pub step_prepare: StepState,
    pub step_download: StepState,
    pub step_hub: StepState,
    pub step_metadata: StepState,
    pub step_start_vms: StepState,
    pub step_ssh: StepState,
    pub step_snapshot: StepState,
    pub vm_phase: HashMap<String, VmPhase>,
    pub vm_cpus: HashMap<String, u8>,
    pub vm_memory_mb: HashMap<String, u32>,
    pub vm_lan_ip: HashMap<String, String>,
    pub vm_ssh_port: HashMap<String, u16>,
    pub vm_problems: HashMap<String, Vec<(String, String)>>,
    pub problem_descs: HashMap<String, String>,
    pub problem_probes: HashMap<String, Vec<String>>,
    pub probes: Option<Arc<Mutex<ProbesState>>>,
    pub last_probes: Option<ProbesState>,
    tick: usize,
    // Step timings
    pub step_prepare_started: Option<Instant>,
    pub step_prepare_elapsed: Option<Duration>,
    pub step_download_started: Option<Instant>,
    pub step_download_elapsed: Option<Duration>,
    pub step_hub_started: Option<Instant>,
    pub step_hub_elapsed: Option<Duration>,
    pub step_metadata_started: Option<Instant>,
    pub step_metadata_elapsed: Option<Duration>,
    pub step_start_vms_started: Option<Instant>,
    pub step_start_vms_elapsed: Option<Duration>,
    pub step_ssh_started: Option<Instant>,
    pub step_ssh_elapsed: Option<Duration>,
    pub step_snapshot_started: Option<Instant>,
    pub step_snapshot_elapsed: Option<Duration>,
    // Snapshot/restore UI state
    pub snapshot_ready: bool,
    pub restoring: bool,
    pub confirm_restore_active: bool,
}

impl UiState {
    /// Create a new UI state for the given scenario and VM list.
    pub fn new(scenario_name: String, scenario_description: String, vm_names: &[String]) -> Self {
        let mut vm_phase = HashMap::new();
        for n in vm_names {
            vm_phase.insert(n.clone(), VmPhase::Pending);
        }
        Self {
            scenario_name,
            scenario_description,
            total_vms: vm_names.len(),
            run_started: Instant::now(),
            run_completed: None,
            quote: None,
            step_prepare: StepState::Pending,
            step_download: StepState::Pending,
            step_hub: StepState::Pending,
            step_metadata: StepState::Pending,
            step_start_vms: StepState::Pending,
            step_ssh: StepState::Pending,
            step_snapshot: StepState::Pending,
            vm_phase,
            vm_cpus: HashMap::new(),
            vm_memory_mb: HashMap::new(),
            vm_lan_ip: HashMap::new(),
            vm_ssh_port: HashMap::new(),
            vm_problems: HashMap::new(),
            problem_descs: HashMap::new(),
            problem_probes: HashMap::new(),
            probes: None,
            last_probes: None,
            tick: 0,
            step_prepare_started: None,
            step_prepare_elapsed: None,
            step_download_started: None,
            step_download_elapsed: None,
            step_hub_started: None,
            step_hub_elapsed: None,
            step_metadata_started: None,
            step_metadata_elapsed: None,
            step_start_vms_started: None,
            step_start_vms_elapsed: None,
            step_ssh_started: None,
            step_ssh_elapsed: None,
            step_snapshot_started: None,
            step_snapshot_elapsed: None,
            snapshot_ready: false,
            restoring: false,
            confirm_restore_active: false,
        }
    }
}

#[derive(Clone, Copy)]
struct Theme {
    primary: Color,
    dim: Color,
    border: Color,
    success: Color,
    warn: Color,
    error: Color,
}

#[must_use]
const fn theme() -> Theme {
    Theme {
        primary: Color::Cyan,
        dim: Color::DarkGray,
        border: Color::Gray,
        success: Color::Green,
        warn: Color::Yellow,
        error: Color::Red,
    }
}

fn step_text(name: &str, s: StepState, tick: usize, suffix: Option<String>) -> Line<'static> {
    let th = theme();
    let mut parts: Vec<Span<'static>> = Vec::new();
    match s {
        StepState::Pending => {
            // Reserve prefix width so labels align with other rows (icon + trailing space)
            parts.push(Span::raw("  "));
        }
        StepState::Running => {
            let chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let sym = chars[tick % chars.len()];
            parts.push(Span::styled(
                format!("{sym} "),
                Style::default().fg(th.primary),
            ));
        }
        StepState::Done => {
            parts.push(Span::styled(
                "✓ ".to_string(),
                Style::default().fg(th.success),
            ));
        }
    }
    parts.push(Span::styled(
        name.to_string(),
        Style::default().add_modifier(Modifier::BOLD),
    ));
    if let Some(suf) = suffix {
        parts.push(Span::styled(
            format!(" ({suf})"),
            Style::default().fg(th.dim),
        ));
    }
    Line::from(parts)
}

fn fmt_dur(d: Duration) -> String {
    if d.as_secs() >= 60 {
        let m = d.as_secs() / 60;
        let s = d.as_secs() % 60;
        format!("{m}m{s:02}s")
    } else {
        let secs = d.as_secs_f32();
        format!("{secs:.1}s")
    }
}

fn measure_wrapped_lines(text: &str, content_width: u16) -> u16 {
    if text.is_empty() {
        return 0;
    }
    let cw = content_width.max(1);
    let mut lines: u16 = 0;
    for raw in text.split('\n') {
        // Approximate by character count; good enough for monospace terminals
        let len = u32::try_from(raw.chars().count()).unwrap_or(0);
        if len == 0 {
            lines = lines.saturating_add(1);
            continue;
        }
        let cw_u32 = u32::from(cw);
        let rows_u32 = len.div_ceil(cw_u32);
        let rows = u16::try_from(rows_u32).unwrap_or(u16::MAX);
        lines = lines.saturating_add(rows.max(1));
    }
    lines
}

// Status color helper removed with tiles view

// tiles view removed (replaced with table view)

fn collect_problem_labels(
    vm_problems: &HashMap<String, Vec<(String, String)>>,
    problem_descs: &HashMap<String, String>,
) -> BTreeSet<String> {
    let mut labels: BTreeSet<String> = BTreeSet::new();
    labels.extend(problem_descs.keys().cloned());
    for plist in vm_problems.values() {
        for (label, _desc) in plist {
            labels.insert(label.clone());
        }
    }
    labels
}

fn build_vm_probe_map(probes: &ProbesState) -> BTreeMap<&str, &Vec<crate::probes::ProbeEntry>> {
    let mut vm_probe_map: BTreeMap<&str, &Vec<crate::probes::ProbeEntry>> = BTreeMap::new();
    for vm in &probes.vms {
        vm_probe_map.insert(&vm.vm_name, &vm.probes);
    }
    vm_probe_map
}

fn problem_lines(
    probes: &ProbesState,
    vm_problems: &HashMap<String, Vec<(String, String)>>,
    problem_descs: &HashMap<String, String>,
    problem_probes: &HashMap<String, Vec<String>>,
) -> (Vec<Line<'static>>, usize, usize) {
    // Collect labels and build VM -> probes map
    let labels = collect_problem_labels(vm_problems, problem_descs);
    let vm_probe_map = build_vm_probe_map(probes);

    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut fixed_pairs = 0usize;
    let mut total_pairs = 0usize;

    for label in labels {
        let desc = problem_descs.get(&label).cloned().unwrap_or_default();

        // For each VM that references this label, collect a leaf line
        let mut vm_entries: Vec<(String, &'static str)> = Vec::new();
        let mut all_ok = true;
        for (vm_name, plist) in vm_problems {
            if !plist.iter().any(|(l, _)| l == &label) {
                continue;
            }
            let entries = if let Some(e) = vm_probe_map.get(vm_name.as_str()) {
                *e
            } else {
                vm_entries.push((vm_name.clone(), "⏳"));
                all_ok = false;
                continue;
            };
            let names = problem_probes.get(&label).cloned().unwrap_or_default();
            let mut total = 0usize;
            let mut passed = 0usize;
            // We only care about pass/fail aggregate; also read fields to satisfy pedantic lints
            for e in entries {
                if names.contains(&e.name) {
                    total += 1;
                    match e.state {
                        ProbeState::Pass { value } => {
                            let _ = value;
                            passed += 1;
                        }
                        ProbeState::Pending { value } => {
                            let _ = value;
                        }
                        ProbeState::Error(ref msg) => {
                            let _ = msg;
                        }
                        ProbeState::MetricNotFound | ProbeState::Waiting => {}
                    }
                }
            }
            if total > 0 {
                total_pairs += 1;
            }
            let icon: &'static str = if total > 0 && passed == total {
                fixed_pairs += 1;
                "✅"
            } else {
                "❌"
            };
            if icon != "✅" {
                all_ok = false;
            }
            vm_entries.push((vm_name.clone(), icon));
        }
        vm_entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Problem header line with aggregate status: ❌ until all assigned VMs are ✅, then ✅
        let agg_icon = if all_ok && !vm_entries.is_empty() {
            "✅"
        } else {
            "❌"
        };
        let icon_style = if agg_icon == "✅" {
            Style::default().fg(theme().success)
        } else {
            Style::default().fg(theme().error)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{agg_icon} "), icon_style),
            Span::styled(
                if desc.is_empty() {
                    label.clone()
                } else {
                    format!("{label}: {desc}")
                },
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]));
        if vm_entries.is_empty() {
            lines.push(Line::from("  - (no VMs)"));
        } else {
            for (vm_name, icon) in vm_entries {
                let icon_style = if icon == "✅" {
                    Style::default().fg(theme().success)
                } else if icon == "⏳" {
                    Style::default().fg(theme().warn)
                } else {
                    Style::default().fg(theme().error)
                };
                lines.push(Line::from(vec![
                    Span::raw("  - "),
                    Span::styled(icon.to_string(), icon_style),
                    Span::raw(format!(" {vm_name}")),
                ]));
            }
        }
    }

    (lines, fixed_pairs, total_pairs)
}

fn render_header(
    f: &mut ratatui::Frame<'_>,
    area: ratatui::prelude::Rect,
    guard: &UiState,
    enable_keys: bool,
) {
    let th = theme();
    // Draw a subtle bottom border as a separator
    let header_border = Block::default()
        .borders(Borders::BOTTOM)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(th.border));
    f.render_widget(header_border, area);

    // Constrain text to the area above the border
    let content_area = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: area.height.saturating_sub(1),
    };
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(content_area);

    let left = Paragraph::new(Line::from(vec![
        Span::styled(
            "intar",
            Style::default().fg(th.primary).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" • "),
        Span::styled(
            guard.scenario_name.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ]));
    f.render_widget(left, cols[0]);

    let help_text = if guard.confirm_restore_active {
        String::from("Confirm reset? [y/N]")
    } else if guard.restoring {
        String::from("Resetting…")
    } else if enable_keys && guard.snapshot_ready {
        String::from("Ctrl+C quit • Ctrl+R reset")
    } else if enable_keys {
        String::from("Ctrl+C quit")
    } else {
        String::from("Ctrl+C (signal) quit")
    };
    let right = Paragraph::new(help_text)
        .style(Style::default().fg(th.dim))
        .alignment(Alignment::Right);
    f.render_widget(right, cols[1]);
}

fn render_description(f: &mut ratatui::Frame<'_>, area: ratatui::prelude::Rect, guard: &UiState) {
    let desc = guard.scenario_description.trim();
    if desc.is_empty() || area.height == 0 {
        // Nothing to render
        return;
    }
    let par = Paragraph::new(desc.to_string())
        .block(Block::default().padding(Padding::new(1, 1, 1, 0)))
        .wrap(ratatui::widgets::Wrap { trim: true })
        .alignment(Alignment::Left);
    f.render_widget(par, area);
}

fn build_steps_lines(guard: &UiState) -> Vec<Line<'static>> {
    let now = Instant::now();
    // Suffix per step: individual time for that step only
    // Download progress in bytes (downloaded, total?) from runtime progress file
    fn read_download_bytes(scenario: &str) -> Option<(u64, Option<u64>)> {
        let dirs = IntarDirs::new().ok()?;
        let path = dirs
            .runtime_scenario_dir(scenario)
            .join("image-download.json");
        let bytes = std::fs::read(&path).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let downloaded = v.get("downloaded").and_then(|x| x.as_u64())?;
        let total = v.get("total").and_then(|x| x.as_u64());
        Some((downloaded, total))
    }
    let prep_suffix = match guard.step_prepare {
        StepState::Pending => None,
        StepState::Running => guard
            .step_prepare_started
            .map(|t| fmt_dur(now.saturating_duration_since(t))),
        StepState::Done => guard.step_prepare_elapsed.map(fmt_dur),
    };
    let dl_suffix = match guard.step_download {
        StepState::Pending => None,
        StepState::Running => {
            let tpart = guard
                .step_download_started
                .map(|t| fmt_dur(now.saturating_duration_since(t)))
                .unwrap_or_default();
            let suffix = if let Some((dl, total)) = read_download_bytes(&guard.scenario_name) {
                let mb = |b: u64| (b as f64) / (1024.0 * 1024.0);
                match total {
                    Some(t) if t > 0 => format!("{:.1}/{:.1} MB • {tpart}", mb(dl), mb(t)),
                    _ => format!("{:.1} MB • {tpart}", mb(dl)),
                }
            } else {
                format!("… • {tpart}")
            };
            Some(suffix)
        }
        StepState::Done => guard.step_download_elapsed.map(fmt_dur),
    };
    let hub_suffix = match guard.step_hub {
        StepState::Pending => None,
        StepState::Running => guard
            .step_hub_started
            .map(|t| fmt_dur(now.saturating_duration_since(t))),
        StepState::Done => guard.step_hub_elapsed.map(fmt_dur),
    };
    let md_suffix = match guard.step_metadata {
        StepState::Pending => None,
        StepState::Running => guard
            .step_metadata_started
            .map(|t| fmt_dur(now.saturating_duration_since(t))),
        StepState::Done => guard.step_metadata_elapsed.map(fmt_dur),
    };
    let start_vms_suffix = match guard.step_start_vms {
        StepState::Pending => None,
        StepState::Running => guard
            .step_start_vms_started
            .map(|t| fmt_dur(now.saturating_duration_since(t))),
        StepState::Done => guard.step_start_vms_elapsed.map(fmt_dur),
    };
    let ssh_suffix = match guard.step_ssh {
        StepState::Pending => None,
        StepState::Running => guard
            .step_ssh_started
            .map(|t| fmt_dur(now.saturating_duration_since(t))),
        StepState::Done => guard.step_ssh_elapsed.map(fmt_dur),
    };
    let snap_suffix = match guard.step_snapshot {
        StepState::Pending => None,
        StepState::Running => guard
            .step_snapshot_started
            .map(|t| fmt_dur(now.saturating_duration_since(t))),
        StepState::Done => guard.step_snapshot_elapsed.map(fmt_dur),
    };

    vec![
        step_text(
            "Downloading image",
            guard.step_download,
            guard.tick,
            dl_suffix,
        ),
        step_text(
            "Preparing resources",
            guard.step_prepare,
            guard.tick,
            prep_suffix,
        ),
        step_text(
            "Starting network hub",
            guard.step_hub,
            guard.tick,
            hub_suffix,
        ),
        step_text(
            "Starting metadata service",
            guard.step_metadata,
            guard.tick,
            md_suffix,
        ),
        step_text(
            &format!(
                "Starting VMs ({}/{})",
                guard
                    .vm_phase
                    .iter()
                    .filter(|(_, p)| matches!(
                        p,
                        VmPhase::Starting | VmPhase::SshWait | VmPhase::Ready
                    ))
                    .count(),
                guard.total_vms
            ),
            guard.step_start_vms,
            guard.tick,
            start_vms_suffix,
        ),
        step_text("Waiting for SSH", guard.step_ssh, guard.tick, ssh_suffix),
        step_text(
            "Saving snapshot",
            guard.step_snapshot,
            guard.tick,
            snap_suffix,
        ),
    ]
}

fn render_steps(
    f: &mut ratatui::Frame<'_>,
    area: ratatui::prelude::Rect,
    guard: &UiState,
    steps: Vec<Line<'static>>,
) {
    let now = Instant::now();
    let overall = guard.run_completed.map_or_else(
        || now.saturating_duration_since(guard.run_started),
        |done| done.saturating_duration_since(guard.run_started),
    );
    let overall_str = fmt_dur(overall);
    let steps_par = Paragraph::new(steps).block(
        Block::bordered()
            .title(Line::from(vec![
                Span::raw(" Boot Sequence "),
                Span::styled(format!("({overall_str})"), Style::default().fg(theme().dim)),
                Span::raw(" "),
            ]))
            .title_alignment(Alignment::Center)
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(theme().border))
            .padding(Padding::new(1, 1, 1, 1)),
    );
    f.render_widget(steps_par, area);
}

fn render_quote(f: &mut ratatui::Frame<'_>, area: ratatui::prelude::Rect, guard: &UiState) {
    if let Some((text, person)) = &guard.quote {
        let content = Line::from(vec![
            Span::styled("“", Style::default().fg(theme().dim)),
            Span::raw(text.clone()),
            Span::styled("” — ", Style::default().fg(theme().dim)),
            Span::styled(
                person.clone(),
                Style::default().add_modifier(Modifier::ITALIC),
            ),
        ]);
        let mut par = Paragraph::new(content).block(
            Block::bordered()
                .title(" Random Stargate Quote ")
                .title_alignment(Alignment::Center)
                .borders(Borders::ALL)
                .border_type(BorderType::Plain)
                .border_style(Style::default().fg(theme().border))
                .padding(Padding::new(1, 1, 1, 1)),
        );
        par = par
            .wrap(ratatui::widgets::Wrap { trim: true })
            .alignment(Alignment::Left);
        f.render_widget(par, area);
    } else {
        // Render an empty spacer block to keep layout stable
        let par = Paragraph::new("").block(Block::default().padding(Padding::new(0, 0, 0, 0)));
        f.render_widget(par, area);
    }
}

const fn phase_label(phase: VmPhase) -> &'static str {
    match phase {
        VmPhase::Pending => "Pending",
        VmPhase::Starting => "Starting",
        VmPhase::SshWait => "SSH",
        VmPhase::Ready => "Ready",
    }
}

// (status span helper inlined into render function)

// --- VM table helpers (extracted to reduce function size) ---
#[derive(Clone)]
struct VmRowData {
    name: String,
    cpu: String,
    ram: String,
    lan: String,
    ssh: String,
    phase: VmPhase,
}

fn center_text(label: &str, width: u16) -> String {
    let len = u16::try_from(label.chars().count()).unwrap_or(0);
    if width <= len {
        return label.to_string();
    }
    let pad = width - len;
    let left = pad / 2;
    let right = pad - left;
    format!(
        "{:<left$}{label}{:>right$}",
        "",
        "",
        left = usize::from(left),
        right = usize::from(right)
    )
}

type WidthMaxes = (u16, u16, u16, u16, u16, u16);
type WidthsAndSpacing = (u16, u16, u16, u16, u16, u16, u16, u16);

fn collect_vm_rows(guard: &UiState) -> (Vec<VmRowData>, WidthMaxes) {
    let mut names: Vec<_> = guard.vm_phase.keys().cloned().collect();
    names.sort();
    let mut rows: Vec<VmRowData> = Vec::with_capacity(names.len());
    let mut max_name = u16::try_from("Name".chars().count()).unwrap_or(0);
    let mut max_cpu = u16::try_from("CPU".chars().count()).unwrap_or(0);
    let mut max_ram = u16::try_from("RAM".chars().count()).unwrap_or(0);
    let mut max_lan = u16::try_from("Internal LAN IP".chars().count()).unwrap_or(0);
    let mut max_ssh = u16::try_from("SSH Port".chars().count()).unwrap_or(0);
    let mut max_status = u16::try_from("Status".chars().count()).unwrap_or(0);
    for name in names {
        let cpu = guard
            .vm_cpus
            .get(&name)
            .copied()
            .map_or_else(|| "-".to_string(), |v| format!("{v}"));
        let ram = guard
            .vm_memory_mb
            .get(&name)
            .copied()
            .map_or_else(|| "-".to_string(), |mb| format!("{mb} MiB"));
        let lan = guard
            .vm_lan_ip
            .get(&name)
            .cloned()
            .unwrap_or_else(|| "-".to_string());
        let ssh = guard
            .vm_ssh_port
            .get(&name)
            .copied()
            .map_or_else(|| "-".to_string(), |p| format!("{p}"));
        let phase = *guard.vm_phase.get(&name).unwrap_or(&VmPhase::Pending);
        max_name = max_name.max(u16::try_from(name.chars().count()).unwrap_or(0));
        max_cpu = max_cpu.max(u16::try_from(cpu.chars().count()).unwrap_or(0));
        max_ram = max_ram.max(u16::try_from(ram.chars().count()).unwrap_or(0));
        max_lan = max_lan.max(u16::try_from(lan.chars().count()).unwrap_or(0));
        max_ssh = max_ssh.max(u16::try_from(ssh.chars().count()).unwrap_or(0));
        max_status = max_status.max(u16::try_from(phase_label(phase).chars().count()).unwrap_or(0));
        rows.push(VmRowData {
            name,
            cpu,
            ram,
            lan,
            ssh,
            phase,
        });
    }
    (
        rows,
        (max_name, max_cpu, max_ram, max_lan, max_ssh, max_status),
    )
}

fn compute_vm_table_widths(area: ratatui::prelude::Rect, maxs: WidthMaxes) -> WidthsAndSpacing {
    let (max_name, max_cpu, max_ram, max_lan, max_ssh, max_status) = maxs;
    let header_pad: u16 = 0;
    let mut name_w = max_name.saturating_add(header_pad);
    let cpu_w = max_cpu.saturating_add(header_pad).max(3);
    let ram_w = max_ram.saturating_add(header_pad).max(3);
    let lan_w = max_lan;
    let ssh_w = max_ssh;
    let mut status_w = max_status.max(u16::try_from("Status".chars().count()).unwrap_or(0));
    status_w = status_w.saturating_add(2).min(20);
    let ncols: u16 = 6;
    let col_spacing: u16 = 3;
    let inner_w = area.width.saturating_sub(2).saturating_sub(2);
    let spacing_total = col_spacing.saturating_mul(ncols.saturating_sub(1));
    let usable_w = inner_w.saturating_sub(spacing_total);
    let total_fixed = cpu_w
        .saturating_add(ram_w)
        .saturating_add(lan_w)
        .saturating_add(ssh_w)
        .saturating_add(status_w);
    if usable_w > total_fixed {
        let available_for_name = usable_w - total_fixed;
        name_w = name_w.min(available_for_name.max(4));
    } else {
        name_w = 4;
    }
    (
        name_w,
        cpu_w,
        ram_w,
        lan_w,
        ssh_w,
        status_w,
        col_spacing,
        usable_w,
    )
}

fn build_vm_header(widths: (u16, u16, u16, u16, u16, u16)) -> Row<'static> {
    let (name_w, cpu_w, ram_w, lan_w, ssh_w, status_w) = widths;
    Row::new(vec![
        Cell::from(Span::styled(
            center_text("Name", name_w),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            center_text("CPU", cpu_w),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            center_text("RAM", ram_w),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            center_text("Internal LAN IP", lan_w),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            center_text("SSH Port", ssh_w),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            center_text("Status", status_w),
            Style::default().add_modifier(Modifier::BOLD),
        )),
    ])
}

fn build_vm_rows(
    rows: Vec<VmRowData>,
    widths: (u16, u16, u16, u16, u16, u16),
) -> Vec<Row<'static>> {
    let (name_w, cpu_w, ram_w, lan_w, ssh_w, status_w) = widths;
    let mut out = Vec::with_capacity(rows.len());
    for VmRowData {
        name,
        cpu,
        ram,
        lan,
        ssh,
        phase,
    } in rows
    {
        let status_span = Span::styled(
            center_text(phase_label(phase), status_w),
            Style::default()
                .fg(match phase {
                    VmPhase::Pending => theme().dim,
                    VmPhase::Starting => theme().warn,
                    VmPhase::SshWait => Color::Blue,
                    VmPhase::Ready => theme().success,
                })
                .add_modifier(Modifier::BOLD),
        );
        out.push(Row::new(vec![
            Cell::from(Span::raw(center_text(&name, name_w))),
            Cell::from(Span::styled(
                center_text(&cpu, cpu_w),
                Style::default().fg(theme().dim),
            )),
            Cell::from(Span::styled(
                center_text(&ram, ram_w),
                Style::default().fg(theme().dim),
            )),
            Cell::from(Span::raw(center_text(&lan, lan_w))),
            Cell::from(Span::styled(
                center_text(&ssh, ssh_w),
                Style::default().fg(theme().dim),
            )),
            Cell::from(status_span),
        ]));
    }
    out
}

fn render_vm_status_table(
    f: &mut ratatui::Frame<'_>,
    area: ratatui::prelude::Rect,
    guard: &UiState,
) {
    let th = theme();
    let (rows_raw, maxs) = collect_vm_rows(guard);
    let (name_w, cpu_w, ram_w, lan_w, ssh_w, status_w, col_spacing, _usable_w) =
        compute_vm_table_widths(area, maxs);
    let widths_arr = [
        Constraint::Length(name_w),
        Constraint::Length(cpu_w),
        Constraint::Length(ram_w),
        Constraint::Length(lan_w),
        Constraint::Length(ssh_w),
        Constraint::Length(status_w),
    ];
    let header = build_vm_header((name_w, cpu_w, ram_w, lan_w, ssh_w, status_w))
        .style(Style::default().fg(th.primary));
    let rows = build_vm_rows(rows_raw, (name_w, cpu_w, ram_w, lan_w, ssh_w, status_w));
    let table = Table::new(rows, widths_arr)
        .header(header)
        .column_spacing(col_spacing)
        .block(
            Block::bordered()
                .title(" VMs ")
                .title_alignment(Alignment::Center)
                .borders(Borders::ALL)
                .border_type(BorderType::Plain)
                .border_style(Style::default().fg(th.border))
                .padding(Padding::new(1, 1, 1, 1)),
        );
    f.render_widget(table, area);
}

fn render_vm_table(f: &mut ratatui::Frame<'_>, area: ratatui::prelude::Rect, guard: &UiState) {
    render_vm_status_table(f, area, guard);
}

fn render_problems_panel(
    f: &mut ratatui::Frame<'_>,
    area: ratatui::prelude::Rect,
    snapshot: Option<&ProbesState>,
    vm_problems_snapshot: &HashMap<String, Vec<(String, String)>>,
    problem_descs_snapshot: &HashMap<String, String>,
    problem_probes_snapshot: &HashMap<String, Vec<String>>,
) {
    if let Some(p) = snapshot {
        let (lines, fixed, total) = problem_lines(
            p,
            vm_problems_snapshot,
            problem_descs_snapshot,
            problem_probes_snapshot,
        );
        let par = Paragraph::new(lines).block(
            Block::bordered()
                .title(format!(" Problems (Fixes {fixed}/{total}) "))
                .title_alignment(Alignment::Center)
                .borders(Borders::ALL)
                .border_type(BorderType::Plain)
                .border_style(Style::default().fg(theme().border))
                .padding(Padding::new(1, 1, 1, 1)),
        );
        f.render_widget(par, area);
        return;
    }

    // Fallback: render declared problems immediately with pending (⏳) VM entries
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut total_pairs = 0usize;

    // Collect all problem labels from declarations and VM references
    let mut labels: BTreeSet<String> = BTreeSet::new();
    labels.extend(problem_descs_snapshot.keys().cloned());
    for plist in vm_problems_snapshot.values() {
        for (label, _desc) in plist {
            labels.insert(label.clone());
        }
    }

    // Build VM->problems quick map for deterministic iteration
    let mut vms_sorted: BTreeMap<&str, &Vec<(String, String)>> = BTreeMap::new();
    for (vm, plist) in vm_problems_snapshot {
        vms_sorted.insert(vm, plist);
    }

    for label in labels {
        let desc = problem_descs_snapshot
            .get(&label)
            .cloned()
            .unwrap_or_default();
        let names = problem_probes_snapshot
            .get(&label)
            .cloned()
            .unwrap_or_default();
        lines.push(Line::from(vec![
            Span::styled("❌ ", Style::default().fg(theme().error)),
            Span::styled(
                if desc.is_empty() {
                    label.clone()
                } else {
                    format!("{label}: {desc}")
                },
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]));
        let mut any_vm = false;
        for (vm_name, plist) in &vms_sorted {
            if !plist.iter().any(|(l, _)| l == &label) {
                continue;
            }
            any_vm = true;
            if !names.is_empty() {
                total_pairs += 1;
            }
            lines.push(Line::from(vec![
                Span::raw("  - "),
                Span::styled("⏳", Style::default().fg(theme().warn)),
                Span::raw(format!(" {vm_name}")),
            ]));
        }
        if !any_vm {
            lines.push(Line::from("  - (no VMs)"));
        }
    }

    let par = Paragraph::new(lines).block(
        Block::bordered()
            .title(format!(" Problems (Fixes 0/{total_pairs}) "))
            .title_alignment(Alignment::Center)
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(theme().border))
            .padding(Padding::new(1, 1, 1, 1)),
    );
    f.render_widget(par, area);
}

fn render_frame(
    f: &mut ratatui::Frame<'_>,
    guard: &UiState,
    enable_keys: bool,
    snapshot: Option<&ProbesState>,
    vm_problems_snapshot: &HashMap<String, Vec<(String, String)>>,
    problem_descs_snapshot: &HashMap<String, String>,
    problem_probes_snapshot: &HashMap<String, Vec<String>>,
) {
    let size = f.size();
    // Quote panel: compute minimum height based on wrapped content + padding + borders
    let quote_min_height: u16 = if let Some((text, person)) = &guard.quote {
        let pad_lr: u16 = 2; // left+right padding total (1 each)
        let pad_tb: u16 = 2; // top+bottom padding total (1 each)
        let borders: u16 = 2; // top+bottom borders
        let content_w = size.width.saturating_sub(pad_lr).saturating_sub(2); // account for borders
        let body = measure_wrapped_lines(&format!("“{text}” — {person}"), content_w);
        body.saturating_add(pad_tb + borders)
    } else {
        0
    };
    // Description paragraph: take only the space it needs, incl. padding
    let desc_height: u16 = if guard.scenario_description.trim().is_empty() {
        0
    } else {
        let pad_lr: u16 = 2; // left+right padding total (1 each)
        let pad_tb: u16 = 1; // top+bottom padding total (top=1, bottom=0)
        let content_w = size.width.saturating_sub(pad_lr);
        let body = measure_wrapped_lines(&guard.scenario_description, content_w);
        body.saturating_add(pad_tb)
    };
    // VM table height: header + one row per VM + borders/padding
    let vms_count = u16::try_from(guard.vm_phase.len()).unwrap_or(0);
    let header_rows: u16 = 1;
    let wrapper_overhead_v: u16 = 4; // borders(2) + padding(2)
    let table_rows = vms_count.saturating_add(header_rows);
    let vm_table_height = table_rows.saturating_add(wrapper_overhead_v).max(5);
    // Steps block height: number of step lines + vertical padding (2) + borders (2)
    let steps_count = {
        let tmp = build_steps_lines(guard);
        u16::try_from(tmp.len()).unwrap_or(0)
    };
    let steps_block_height: u16 = steps_count.saturating_add(4);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            // Tighten header to remove extra gap above quotes box
            Constraint::Length(2),
            Constraint::Length(desc_height),
            Constraint::Length(quote_min_height),
            // Steps block height (dynamic)
            Constraint::Length(steps_block_height),
            Constraint::Length(vm_table_height),
            Constraint::Min(3),
        ])
        .split(size);
    render_header(f, chunks[0], guard, enable_keys);
    render_description(f, chunks[1], guard);
    render_quote(f, chunks[2], guard);
    // Build steps once for height and reuse for rendering
    let steps_lines = build_steps_lines(guard);
    render_steps(f, chunks[3], guard, steps_lines);
    render_vm_table(f, chunks[4], guard);
    render_problems_panel(
        f,
        chunks[5],
        snapshot,
        vm_problems_snapshot,
        problem_descs_snapshot,
        problem_probes_snapshot,
    );

    // Draw confirmation modal on top when active
    if guard.confirm_restore_active {
        render_confirm_modal(f, size, guard);
    }
}

fn render_confirm_modal(f: &mut ratatui::Frame<'_>, area: Rect, guard: &UiState) {
    // Centered rectangle (60% width, 30% height)
    let outer = area;
    let vw = outer.width;
    let vh = outer.height;
    let mw = (vw.saturating_mul(60) / 100).max(30); // min width ~30 cols
    let mh = (vh.saturating_mul(30) / 100).max(7); // min height ~7 rows
    let x = outer.x + (vw.saturating_sub(mw)) / 2;
    let y = outer.y + (vh.saturating_sub(mh)) / 2;
    let modal = Rect {
        x,
        y,
        width: mw,
        height: mh,
    };

    // Clear background under modal
    f.render_widget(Clear, modal);

    let th = theme();

    let scenario = guard.scenario_name.clone();
    let total_vms = guard.total_vms;

    let lines = vec![
        Line::from("").alignment(Alignment::Center),
        Line::from(vec![
            Span::styled("⚠ ", Style::default().fg(th.warn)),
            Span::styled(
                "Reset to last save point?".to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ])
        .alignment(Alignment::Center),
        Line::from("").alignment(Alignment::Center),
        Line::from(Span::styled(
            format!("Scenario: {scenario} • VMs: {total_vms}"),
            Style::default().fg(th.dim),
        ))
        .alignment(Alignment::Center),
        Line::from("").alignment(Alignment::Center),
        Line::from(Span::styled(
            "Resets all VMs to the saved checkpoint.",
            Style::default().fg(th.dim),
        ))
        .alignment(Alignment::Center),
        Line::from(Span::styled(
            "Unsaved progress inside VMs will be lost.",
            Style::default().fg(th.error),
        ))
        .alignment(Alignment::Center),
        Line::from(Span::styled(
            "This action cannot be undone.",
            Style::default().fg(th.warn),
        ))
        .alignment(Alignment::Center),
        Line::from("").alignment(Alignment::Center),
        Line::from(vec![
            Span::styled("[y]", Style::default().fg(th.success)),
            Span::raw(" Reset   "),
            Span::styled("[N]/Esc", Style::default()),
            Span::raw(" Cancel "),
            Span::styled("(default)", Style::default().fg(th.dim)),
        ])
        .alignment(Alignment::Center),
    ];

    let block = Block::bordered()
        .title(" Reset ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(th.warn))
        .padding(Padding::new(1, 1, 1, 1));

    let par = Paragraph::new(lines)
        .alignment(Alignment::Center)
        .block(block);
    f.render_widget(par, modal);
}

fn spawn_draw_task(
    shared: Arc<Mutex<UiState>>,
    enable_keys: bool,
    quit_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if enable_keys {
            let _ = enable_raw_mode();
        }
        let mut stdout = stdout();
        let _ = execute!(stdout, EnterAlternateScreen);
        let backend = ratatui::backend::CrosstermBackend::new(stdout);
        let mut term = ratatui::Terminal::new(backend).unwrap();
        let draw_quit_rx = quit_rx;
        loop {
            if *draw_quit_rx.borrow() {
                break;
            }
            let mut guard = shared.lock().await;
            guard.tick = guard.tick.wrapping_add(1);
            // Try to refresh last_probes snapshot without blocking draw; if lock fails, keep previous
            let snapshot_arc = guard.probes.clone();
            if let Some(pstate) = snapshot_arc.as_ref()
                && let Ok(p) = pstate.try_lock()
            {
                guard.last_probes = Some(p.clone());
            }
            let vm_problems_snapshot = guard.vm_problems.clone();
            let problem_descs_snapshot = guard.problem_descs.clone();
            let problem_probes_snapshot = guard.problem_probes.clone();
            term.draw(|f| {
                render_frame(
                    f,
                    &guard,
                    enable_keys,
                    guard.last_probes.as_ref(),
                    &vm_problems_snapshot,
                    &problem_descs_snapshot,
                    &problem_probes_snapshot,
                );
            })
            .ok();
            drop(guard);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        // Restore terminal state cooperatively
        let _ = term.show_cursor();
        if enable_keys {
            let _ = disable_raw_mode();
        }
        let mut out = std::io::stdout();
        let _ = execute!(out, LeaveAlternateScreen);
    })
}

fn spawn_input_task(
    enable_keys: bool,
    quit_tx: tokio::sync::watch::Sender<bool>,
    quit_rx: tokio::sync::watch::Receiver<bool>,
    shared: Arc<Mutex<UiState>>,
    action_tx: broadcast::Sender<UiAction>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !enable_keys {
        return None;
    }
    let input_quit = quit_tx;
    let input_quit_rx = quit_rx;
    let state = shared;
    let actions = action_tx;
    Some(tokio::spawn(async move {
        // Poll keyboard events for Ctrl+C (inside TUI)
        loop {
            if *input_quit_rx.borrow() {
                break;
            }
            // Use blocking poll/read within tokio task; short poll timeout
            if event::poll(std::time::Duration::from_millis(100)).unwrap_or(false)
                && let Ok(Event::Key(key)) = event::read()
                && key.kind == KeyEventKind::Press
            {
                // Confirm flow: if confirmation modal active, only accept y/N
                if let Ok(guard) = state.try_lock()
                    && guard.confirm_restore_active
                {
                    drop(guard);
                    match key.code {
                        KeyCode::Char('y' | 'Y') => {
                            let _ = actions.send(UiAction::ConfirmRestore(true));
                        }
                        KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                            let _ = actions.send(UiAction::ConfirmRestore(false));
                        }
                        _ => {}
                    }
                    // handled; continue polling
                    continue;
                }
                // Regular shortcuts
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    let _ = input_quit.send(true);
                    break;
                }
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('r') {
                    let _ = actions.send(UiAction::RestoreRequested);
                }
            }
        }
    }))
}

/// Active TUI instance; owns draw/input tasks and quit signaling.
pub struct RunUi {
    pub state: Arc<Mutex<UiState>>,
    handle: tokio::task::JoinHandle<()>,
    input_handle: Option<tokio::task::JoinHandle<()>>,
    quit_tx: tokio::sync::watch::Sender<bool>,
    quit_rx: tokio::sync::watch::Receiver<bool>,
    action_tx: broadcast::Sender<UiAction>,
}

impl RunUi {
    /// Create a new TUI with defaults (keys enabled unless disabled by env).
    pub fn new(initial: UiState) -> Self {
        // Default: enable key handling unless env disables it
        let enable_keys = std::env::var("INTAR_TUI_DISABLE_KEYS").map_or(true, |v| {
            let val = v.to_ascii_lowercase();
            !(val == "1" || val == "true" || val == "on" || val == "yes")
        });
        Self::new_with_options(initial, enable_keys)
    }

    /// Create a new TUI with explicit key handling enablement.
    ///
    /// When `enable_keys` is `true`, the TUI enables raw mode and listens for
    /// Ctrl+C as an in-TUI quit request. When `false`, raw mode is not enabled
    /// and no keys are read.
    pub fn new_with_options(initial: UiState, enable_keys: bool) -> Self {
        let shared = Arc::new(Mutex::new(initial));
        let (quit_tx, quit_rx) = tokio::sync::watch::channel(false);
        let (action_tx, _action_rx) = broadcast::channel(16);
        let handle = spawn_draw_task(shared.clone(), enable_keys, quit_rx.clone());
        let input_handle = spawn_input_task(
            enable_keys,
            quit_tx.clone(),
            quit_rx.clone(),
            shared.clone(),
            action_tx.clone(),
        );
        Self {
            state: shared,
            handle,
            input_handle,
            quit_tx,
            quit_rx,
            action_tx,
        }
    }

    /// Request cooperative shutdown and join the TUI tasks.
    pub async fn stop(self) {
        // Request cooperative shutdown and join tasks
        let _ = self.quit_tx.send(true);
        let _ = self.handle.await;
        if let Some(h) = self.input_handle {
            let _ = h.await;
        }
    }

    /// Wait until the TUI receives a quit request (e.g., Ctrl+C in-TUI).
    pub async fn wait_for_quit(&self) {
        let mut rx = self.quit_rx.clone();
        if *rx.borrow() {
            return;
        }
        let _ = rx.changed().await;
    }

    /// Clone a receiver to observe quit events (non-blocking checks allowed).
    pub fn quit_receiver(&self) -> tokio::sync::watch::Receiver<bool> {
        self.quit_rx.clone()
    }

    /// Returns true if a quit was requested.
    pub fn quit_requested(&self) -> bool {
        *self.quit_rx.borrow()
    }

    /// Subscribe to UI actions (e.g., Ctrl+R restore request, confirmations).
    pub fn action_subscribe(&self) -> broadcast::Receiver<UiAction> {
        self.action_tx.subscribe()
    }
}

/// UI actions emitted by the input task and consumed in the main loop.
#[derive(Clone, Debug)]
pub enum UiAction {
    RestoreRequested,
    ConfirmRestore(bool),
}
