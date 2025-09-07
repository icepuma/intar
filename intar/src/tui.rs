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
use ratatui::prelude::{Color, Constraint, Direction, Layout, Line, Modifier, Span, Style};
use ratatui::widgets::block::Padding;
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::stdout;
use std::sync::Arc;
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
    pub total_vms: usize,
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
}

impl UiState {
    /// Create a new UI state for the given scenario and VM list.
    pub fn new(scenario_name: String, vm_names: &[String]) -> Self {
        let mut vm_phase = HashMap::new();
        for n in vm_names {
            vm_phase.insert(n.clone(), VmPhase::Pending);
        }
        Self {
            scenario_name,
            total_vms: vm_names.len(),
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
        }
    }
}

fn step_text(name: &str, s: StepState, tick: usize) -> Line<'static> {
    let (sym, style) = match s {
        StepState::Pending => ("  ", Style::default().fg(Color::DarkGray)),
        StepState::Running => {
            let chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            (chars[tick % chars.len()], Style::default().fg(Color::Cyan))
        }
        StepState::Done => ("✓", Style::default().fg(Color::Green)),
    };
    Line::from(vec![
        Span::styled(format!(" {sym} "), style),
        Span::styled(
            name.to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ])
}

fn vm_rows(state: &UiState) -> Vec<Row<'static>> {
    let mut names: Vec<_> = state.vm_phase.keys().cloned().collect();
    names.sort();
    names
        .into_iter()
        .map(|n| {
            let p = *state.vm_phase.get(&n).unwrap_or(&VmPhase::Pending);
            let icon = match p {
                VmPhase::Pending => " ",
                VmPhase::Starting => "⏳",
                VmPhase::SshWait => "🔐",
                VmPhase::Ready => "✅",
            };
            let status = match p {
                VmPhase::Pending => "pending".to_string(),
                VmPhase::Starting => "starting".to_string(),
                VmPhase::SshWait => "waiting for ssh".to_string(),
                VmPhase::Ready => state
                    .vm_ssh_port
                    .get(&n)
                    .map_or_else(|| "ready".to_string(), |p| format!("ready :{p}")),
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
            Row::new(vec![
                Cell::from(icon),
                Cell::from(n),
                Cell::from(cpus),
                Cell::from(mem),
                Cell::from(lan),
                Cell::from(ssh),
                Cell::from(status),
            ])
        })
        .collect()
}

fn problem_lines(
    probes: &ProbesState,
    vm_problems: &HashMap<String, Vec<(String, String)>>,
    problem_descs: &HashMap<String, String>,
    problem_probes: &HashMap<String, Vec<String>>,
) -> (Vec<Line<'static>>, usize, usize) {
    // Collect all problem labels
    let mut labels: BTreeSet<String> = BTreeSet::new();
    labels.extend(problem_descs.keys().cloned());
    for plist in vm_problems.values() {
        for (label, _desc) in plist {
            labels.insert(label.clone());
        }
    }

    // Index VM -> probes entries
    let mut vm_probe_map: BTreeMap<&str, &Vec<crate::probes::ProbeEntry>> = BTreeMap::new();
    for vm in &probes.vms {
        vm_probe_map.insert(&vm.vm_name, &vm.probes);
    }

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
        lines.push(Line::from(vec![
            Span::raw(format!("{agg_icon} ")),
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
                lines.push(Line::from(format!("  - {icon} {vm_name}")));
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
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "intar • ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            guard.scenario_name.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            if enable_keys {
                "Ctrl+C to stop & clean up".to_string()
            } else {
                "Ctrl+C (signal) to stop & clean up".to_string()
            },
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(Block::default().padding(Padding::new(0, 0, 0, 1)));
    f.render_widget(title, area);
}

fn render_steps(f: &mut ratatui::Frame<'_>, area: ratatui::prelude::Rect, guard: &UiState) {
    let steps = vec![
        step_text("Preparing resources", guard.step_prepare, guard.tick),
        step_text("Starting network hub", guard.step_hub, guard.tick),
        step_text("Starting metadata service", guard.step_metadata, guard.tick),
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
        ),
        step_text("Waiting for SSH", guard.step_ssh, guard.tick),
    ];
    let steps_par = Paragraph::new(steps).block(
        Block::bordered()
            .title(" Boot Sequence ")
            .padding(Padding::new(1, 1, 0, 1)),
    );
    f.render_widget(steps_par, area);
}

fn render_quote(f: &mut ratatui::Frame<'_>, area: ratatui::prelude::Rect, guard: &UiState) {
    if let Some((text, person)) = &guard.quote {
        let content = Line::from(vec![
            Span::styled("“", Style::default().fg(Color::DarkGray)),
            Span::raw(text.clone()),
            Span::styled("” — ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                person.clone(),
                Style::default().add_modifier(Modifier::ITALIC),
            ),
        ]);
        let mut par = Paragraph::new(content).block(
            Block::bordered()
                .title(" Random Stargate Quotes ")
                .padding(Padding::new(1, 1, 1, 1)),
        );
        par = par.wrap(ratatui::widgets::Wrap { trim: true });
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
            Constraint::Length(2),      // icon
            Constraint::Percentage(18), // VM
            Constraint::Length(5),      // CPU
            Constraint::Length(7),      // Mem
            Constraint::Length(16),     // LAN
            Constraint::Length(8),      // SSH
            Constraint::Percentage(46), // Status
        ],
    )
    .header(
        Row::new(vec!["", "VM", "CPU", "Mem", "LAN", "SSH", "Status"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::bordered()
            .title(" VM Status ")
            .padding(Padding::new(1, 1, 0, 1)),
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
                .padding(Padding::new(1, 1, 0, 1)),
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
            Span::raw("❌ "),
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
            lines.push(Line::from(format!("  - ⏳ {vm_name}")));
        }
        if !any_vm {
            lines.push(Line::from("  - (no VMs)"));
        }
    }

    let par = Paragraph::new(lines).block(
        Block::bordered()
            .title(format!(" Problems (Fixes 0/{total_pairs}) "))
            .padding(Padding::new(1, 1, 0, 1)),
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
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Length(10),
            Constraint::Min(6),
            Constraint::Min(6),
        ])
        .split(size);
    render_header(f, chunks[0], guard, enable_keys);
    render_quote(f, chunks[1], guard);
    render_steps(f, chunks[2], guard);
    render_vm_table(f, chunks[3], guard);
    render_problems_panel(
        f,
        chunks[4],
        snapshot,
        vm_problems_snapshot,
        problem_descs_snapshot,
        problem_probes_snapshot,
    );
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
    #[allow(clippy::too_many_lines)]
    pub fn new_with_options(initial: UiState, enable_keys: bool) -> Self {
        let shared = Arc::new(Mutex::new(initial));
        let (quit_tx, quit_rx) = tokio::sync::watch::channel(false);
        let shared_clone = shared.clone();
        let draw_quit_rx = quit_rx.clone();
        let handle = tokio::spawn(async move {
            // setup terminal
            if enable_keys {
                let _ = enable_raw_mode();
            }
            let mut stdout = stdout();
            let _ = execute!(stdout, EnterAlternateScreen);
            let backend = ratatui::backend::CrosstermBackend::new(stdout);
            let mut term = ratatui::Terminal::new(backend).unwrap();
            loop {
                if *draw_quit_rx.borrow() {
                    break;
                }
                let mut guard = shared_clone.lock().await;
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
        });
        let input_handle = if enable_keys {
            let input_quit = quit_tx.clone();
            let input_quit_rx = quit_rx.clone();
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
        } else {
            None
        };
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
