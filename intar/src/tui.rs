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
use ratatui::prelude::{
    Alignment, Color, Constraint, Direction, Layout, Line, Modifier, Rect, Span, Style,
};
use ratatui::widgets::block::Padding;
use ratatui::widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::stdout;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

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
    pub step_hub: StepState,
    pub step_metadata: StepState,
    pub step_start_vms: StepState,
    pub step_ssh: StepState,
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
    pub step_hub_started: Option<Instant>,
    pub step_hub_elapsed: Option<Duration>,
    pub step_metadata_started: Option<Instant>,
    pub step_metadata_elapsed: Option<Duration>,
    pub step_start_vms_started: Option<Instant>,
    pub step_start_vms_elapsed: Option<Duration>,
    pub step_ssh_started: Option<Instant>,
    pub step_ssh_elapsed: Option<Duration>,
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
            step_hub: StepState::Pending,
            step_metadata: StepState::Pending,
            step_start_vms: StepState::Pending,
            step_ssh: StepState::Pending,
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
            step_hub_started: None,
            step_hub_elapsed: None,
            step_metadata_started: None,
            step_metadata_elapsed: None,
            step_start_vms_started: None,
            step_start_vms_elapsed: None,
            step_ssh_started: None,
            step_ssh_elapsed: None,
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

fn vm_rows(state: &UiState) -> Vec<Row<'static>> {
    let th = theme();
    let mut names: Vec<_> = state.vm_phase.keys().cloned().collect();
    names.sort();
    let mut rows: Vec<Row<'static>> = Vec::new();
    for n in names {
        let p = *state.vm_phase.get(&n).unwrap_or(&VmPhase::Pending);
        let status_style = match p {
            VmPhase::Pending => Style::default().fg(th.dim),
            VmPhase::Starting | VmPhase::SshWait => Style::default().fg(th.warn),
            VmPhase::Ready => Style::default().fg(th.success),
        };
        let status = match p {
            VmPhase::Pending => String::from("pending"),
            VmPhase::Starting => String::from("starting"),
            VmPhase::SshWait => String::from("waiting for ssh"),
            VmPhase::Ready => state
                .vm_ssh_port
                .get(&n)
                .map_or_else(|| String::from("ready"), |p| format!("ready :{p}")),
        };
        let cpus = state
            .vm_cpus
            .get(&n)
            .map_or_else(|| String::from("-"), ToString::to_string);
        let mem = state
            .vm_memory_mb
            .get(&n)
            .map_or_else(|| String::from("-"), |m| format!("{m}MB"));
        let lan = state
            .vm_lan_ip
            .get(&n)
            .cloned()
            .unwrap_or_else(|| String::from("-"));
        let ssh = state
            .vm_ssh_port
            .get(&n)
            .map_or_else(|| String::from("-"), |p| format!(":{p}"));
        let row = Row::new(vec![
            Cell::from(n.clone()).style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from(cpus.to_string()).style(Style::default().fg(Color::Gray)),
            Cell::from(mem.to_string()).style(Style::default().fg(Color::Gray)),
            Cell::from(lan.to_string()).style(Style::default().fg(Color::Gray)),
            Cell::from(ssh.to_string()).style(Style::default().fg(th.primary)),
            Cell::from(status.to_string()).style(status_style),
        ])
        .height(1);
        rows.push(row);
    }
    rows
}

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

    let help_text = if enable_keys {
        String::from("Ctrl+C to stop & clean up")
    } else {
        String::from("Ctrl+C (signal) to stop & clean up")
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

fn render_steps(f: &mut ratatui::Frame<'_>, area: ratatui::prelude::Rect, guard: &UiState) {
    let now = Instant::now();
    // Overall boot timer for the title: run from run_started until run_completed (if set)
    let overall = guard.run_completed.map_or_else(
        || now.saturating_duration_since(guard.run_started),
        |done| done.saturating_duration_since(guard.run_started),
    );
    let overall_str = fmt_dur(overall);

    // Suffix per step: individual time for that step only
    let prep_suffix = match guard.step_prepare {
        StepState::Pending => None,
        StepState::Running => guard
            .step_prepare_started
            .map(|t| fmt_dur(now.saturating_duration_since(t))),
        StepState::Done => guard.step_prepare_elapsed.map(fmt_dur),
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

    let steps = vec![
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
    ];
    let steps_par = Paragraph::new(steps).block(
        Block::bordered()
            .title(Line::from(vec![
                Span::raw(" Boot Sequence "),
                Span::styled(format!("({overall_str})"), Style::default().fg(theme().dim)),
                Span::raw(" "),
            ]))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
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
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
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

fn render_vm_table(f: &mut ratatui::Frame<'_>, area: ratatui::prelude::Rect, guard: &UiState) {
    let rows = vm_rows(guard);
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(18), // VM
            Constraint::Length(5),      // CPU
            Constraint::Length(7),      // Mem
            Constraint::Length(16),     // LAN
            Constraint::Length(8),      // SSH
            Constraint::Percentage(46), // Status
        ],
    )
    .column_spacing(1)
    .header(
        Row::new(vec!["VM", "CPU", "Mem", "LAN", "SSH", "Status"]) //
            .style(
                Style::default()
                    .fg(theme().primary)
                    .add_modifier(Modifier::BOLD),
            )
            .height(1),
    )
    .block(
        Block::bordered()
            .title(" VM Status ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(theme().border))
            .padding(Padding::new(1, 1, 1, 1)),
    );
    f.render_widget(table, area);
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
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
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
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
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
    // VM table height: header(1) + rows(1 each) + top/bottom padding(2) + borders(2)
    let vm_rows = u16::try_from(guard.vm_phase.len()).unwrap_or(0);
    let vm_table_height: u16 = 1 + vm_rows + 2 + 2;
    let vm_table_height = vm_table_height.max(5); // minimum to show header + padding + borders
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            // Tighten header to remove extra gap above quotes box
            Constraint::Length(2),
            Constraint::Length(desc_height),
            Constraint::Length(quote_min_height),
            // Exactly 5 items tall: 5 lines + 1 bottom padding + 2 borders = 8
            Constraint::Length(9),
            Constraint::Length(vm_table_height),
            Constraint::Min(3),
        ])
        .split(size);
    render_header(f, chunks[0], guard, enable_keys);
    render_description(f, chunks[1], guard);
    render_quote(f, chunks[2], guard);
    render_steps(f, chunks[3], guard);
    render_vm_table(f, chunks[4], guard);
    render_problems_panel(
        f,
        chunks[5],
        snapshot,
        vm_problems_snapshot,
        problem_descs_snapshot,
        problem_probes_snapshot,
    );
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
) -> Option<tokio::task::JoinHandle<()>> {
    if !enable_keys {
        return None;
    }
    let input_quit = quit_tx;
    let input_quit_rx = quit_rx;
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
                && key.modifiers.contains(KeyModifiers::CONTROL)
                && key.code == KeyCode::Char('c')
            {
                let _ = input_quit.send(true);
                break;
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
        let handle = spawn_draw_task(shared.clone(), enable_keys, quit_rx.clone());
        let input_handle = spawn_input_task(enable_keys, quit_tx.clone(), quit_rx.clone());
        Self {
            state: shared,
            handle,
            input_handle,
            quit_tx,
            quit_rx,
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
}
