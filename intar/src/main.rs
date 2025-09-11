use anyhow::{Context, Result as AnyhowResult, bail};
use clap::{Parser, Subcommand};
use intar::embedded_agent;
// TUI handles UX; non-interactive logs are also emitted
use intar::VmStatus;
use intar::scenario_runner::ScenarioRunner;
use intar_local_backend::Backend;
use intar_scenario::{list_embedded_scenarios, read_embedded_scenario};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "intar")]
#[command(about = "A CLI tool for managing intar scenarios")]
#[command(version)]
#[command(
    after_help = "Examples:\n  intar scenario list\n  intar scenario run multiple-rocky-linux-vms  # starts scenario in foreground; Ctrl+C to stop\n  intar scenario status multiple-rocky-linux-vms\n  intar scenario ssh multiple-rocky-linux-vms web\n"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

// Platform-specific signal waiters at module scope to satisfy clippy pedantic
#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigint = signal(SignalKind::interrupt()).expect("sigint");
    let mut sighup = signal(SignalKind::hangup()).expect("sighup");
    let mut sigterm = signal(SignalKind::terminate()).expect("sigterm");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigint.recv() => {},
        _ = sighup.recv() => {},
        _ = sigterm.recv() => {},
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

type SshEndpoint = (String, String, u16, String, String); // (vm_name, host, port, user, key_path)

mod metrics;
mod probes;
mod quotes;
mod tui;

fn hub_port_for_scenario(name: &str) -> u16 {
    let sid = intar_local_backend::cloud_init::calculate_scenario_id(name);
    intar_local_backend::constants::hub_port(sid)
}

fn start_hub_task(scenario_name: &str) -> (tokio::task::JoinHandle<()>, u16) {
    let port = hub_port_for_scenario(scenario_name);
    tracing::info!(
        "Starting internal UDP hub for '{}' on 127.0.0.1:{}",
        scenario_name,
        port
    );
    let scenario_name_for_hub = scenario_name.to_string();
    let handle = tokio::spawn(async move {
        let _ = intar_local_backend::hub::run_udp_hub(&scenario_name_for_hub, port).await;
    });
    (handle, port)
}

fn start_metadata_task(scenario_name: &str) -> (tokio::task::JoinHandle<()>, u16) {
    let sid = intar_local_backend::cloud_init::calculate_scenario_id(scenario_name);
    let port = intar_local_backend::constants::metadata_port(sid);
    tracing::info!(
        "Starting metadata server for '{}' on 127.0.0.1:{}",
        scenario_name,
        port
    );
    let scenario_name_for_md = scenario_name.to_string();
    let handle = tokio::spawn(async move {
        let _ =
            intar_local_backend::metadata::run_metadata_server(&scenario_name_for_md, port).await;
    });
    (handle, port)
}

fn sorted_vm_names(runner: &ScenarioRunner) -> Vec<String> {
    let mut names: Vec<String> = runner.vms.keys().cloned().collect();
    names.sort();
    names
}

fn init_console_logging() {
    use tracing_subscriber::{EnvFilter, fmt};
    let _ = fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .try_init();
}

fn init_file_logging_for_run(scenario_name: &str) -> AnyhowResult<std::path::PathBuf> {
    use tracing_subscriber::fmt;
    let dirs = intar::IntarDirs::new()?;
    let dir = dirs.runtime_scenario_dir(scenario_name);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("scenario.log");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let writer = move || file.try_clone().unwrap();
    let subscriber = fmt()
        .with_target(false)
        .with_ansi(false)
        .compact()
        .with_writer(writer)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
    Ok(path)
}

async fn collect_ssh_endpoints(
    runner: &ScenarioRunner,
    vm_names: &[String],
    scenario_name: &str,
) -> AnyhowResult<Vec<SshEndpoint>> {
    which::which("ssh").context("'ssh' binary not found in PATH")?;
    let mut endpoints = Vec::with_capacity(vm_names.len());
    for name in vm_names {
        if let Some(vm) = runner.vms.get(name) {
            let info = vm
                .ssh_info()
                .await
                .with_context(|| format!("Failed to get SSH info for VM '{name}'"))?;
            let key_path = info
                .private_key_path
                .ok_or_else(|| anyhow::anyhow!("Missing private key path for VM '{name}'"))?;
            if !std::path::Path::new(&key_path).exists() {
                anyhow::bail!("Scenario SSH key not found: {key_path}");
            }
            endpoints.push((
                name.clone(),
                info.host,
                info.port,
                "intar".to_string(),
                key_path,
            ));
        } else {
            anyhow::bail!(
                "VM '{}' not found in scenario '{}' while collecting SSH info",
                name,
                scenario_name
            );
        }
    }
    Ok(endpoints)
}

// old SSH spinner + overview removed; handled by TUI

#[derive(Subcommand)]
enum Commands {
    /// Scenario management commands
    Scenario {
        #[command(subcommand)]
        action: ScenarioCommands,
    },
    // No other top-level commands
}

#[derive(Subcommand)]
enum ScenarioCommands {
    /// List all available scenarios
    List,
    /// Run a scenario (creates and starts all VMs)
    Run {
        /// Name of the scenario to run
        name: String,
    },
    /// Show status of a scenario's VMs
    Status {
        /// Name of the scenario to check
        name: String,
    },
    /// SSH into a VM within a scenario
    Ssh {
        /// Name of the scenario containing the VM
        scenario: String,
        /// Name of the VM to SSH into
        vm: String,
    },
}

#[tokio::main]
async fn main() -> AnyhowResult<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scenario { action } => match action {
            ScenarioCommands::List => {
                // Console logs for non-run commands
                init_console_logging();
                let scenarios = list_embedded_scenarios();

                if scenarios.is_empty() {
                    tracing::info!("No scenarios found.");
                    return Ok(());
                }

                tracing::info!("Available scenarios:");
                for scenario_file in &scenarios {
                    match read_embedded_scenario(scenario_file) {
                        Ok(scenario) => {
                            tracing::info!("Name: {} - File: {}", scenario.name, scenario_file);
                            if !scenario.description.is_empty() {
                                tracing::info!("Description: {}", scenario.description);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("{} - (error parsing: {})", scenario_file, e);
                        }
                    }
                }
            }
            ScenarioCommands::Run { name } => {
                run_scenario(&name).await?;
            }
            ScenarioCommands::Status { name } => {
                init_console_logging();
                status_scenario(&name).await?;
            }
            ScenarioCommands::Ssh { scenario, vm } => {
                init_console_logging();
                ssh_into_vm(&scenario, &vm).await?;
            }
        },
        // Internal commands removed; UDP hub runs in-process only
    }

    Ok(())
}

// Hub now lives in intar-local-backend::hub

fn find_scenario_by_name(name: &str) -> AnyhowResult<String> {
    let scenarios = list_embedded_scenarios();

    if scenarios.is_empty() {
        bail!("No scenarios available. Please check your installation.");
    }

    // Collect valid scenario names for better error messages
    let mut available_scenarios = Vec::new();

    for scenario_file in scenarios {
        match read_embedded_scenario(&scenario_file) {
            Ok(scenario) => {
                available_scenarios.push(scenario.name.clone());
                if scenario.name.to_lowercase() == name.to_lowercase() {
                    return Ok(scenario_file);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to parse scenario file '{}' : {}", scenario_file, e);
            }
        }
    }

    bail!(
        "Scenario '{}' not found.\nAvailable scenarios: {}",
        name,
        if available_scenarios.is_empty() {
            "none (all scenario files failed to parse)".to_string()
        } else {
            available_scenarios.join(", ")
        }
    )
}

fn build_vm_names(scenario: &intar_scenario::Scenario) -> Vec<String> {
    let mut vm_names: Vec<String> = scenario.vm.keys().cloned().collect();
    vm_names.sort();
    vm_names
}

fn create_ui(
    scenario_name: &str,
    scenario_description: &str,
    vm_names: &[String],
) -> crate::tui::RunUi {
    let st = crate::tui::UiState::new(
        scenario_name.to_string(),
        scenario_description.to_string(),
        vm_names,
    );
    crate::tui::RunUi::new(st)
}

async fn populate_static_vm_info(
    runner: &ScenarioRunner,
    ui: &crate::tui::RunUi,
    vm_names: &[String],
) {
    let sid = intar_local_backend::cloud_init::calculate_scenario_id(&runner.scenario.name);
    let mut st = ui.state.lock().await;
    for (plabel, pdef) in &runner.scenario.problems {
        st.problem_descs
            .insert(plabel.clone(), pdef.description.clone());
        let names: Vec<String> = pdef.probes.keys().cloned().collect();
        st.problem_probes.insert(plabel.clone(), names);
    }
    for (idx, name) in vm_names.iter().enumerate() {
        if let Some(cfg) = runner.scenario.vm.get(name) {
            st.vm_cpus.insert(name.clone(), cfg.cpus);
            st.vm_memory_mb.insert(name.clone(), cfg.memory);
            if !cfg.problems.is_empty() {
                let mut vec = Vec::new();
                for plabel in &cfg.problems {
                    if let Some(prob) = runner.scenario.problems.get(plabel) {
                        vec.push((plabel.clone(), prob.description.clone()));
                    } else {
                        vec.push((plabel.clone(), String::new()));
                    }
                }
                st.vm_problems.insert(name.clone(), vec);
            }
        }
        let idx_u8 = u8::try_from(idx).unwrap_or(u8::MAX);
        let lan = intar_local_backend::constants::lan_ip(sid, idx_u8);
        st.vm_lan_ip.insert(name.clone(), lan);
    }
}

async fn prepare_and_start_services(
    runner: &mut ScenarioRunner,
    ui: &crate::tui::RunUi,
) -> AnyhowResult<(
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
    String,
)> {
    {
        let mut st = ui.state.lock().await;
        // Download step starts first (shows percent from progress file)
        st.step_download = crate::tui::StepState::Running;
        if st.step_download_started.is_none() {
            st.step_download_started = Some(Instant::now());
        }
        // Keep "Preparing resources" pending to avoid dual spinners during download
        st.step_prepare = crate::tui::StepState::Pending;
        st.step_prepare_started = None;
    }
    runner
        .prepare()
        .await
        .context("Failed to prepare scenario")?;
    {
        let mut st = ui.state.lock().await;
        st.step_download = crate::tui::StepState::Done;
        if let Some(t0) = st.step_download_started.take() {
            st.step_download_elapsed = Some(t0.elapsed());
        }
        // Mark prepare as done without a spinner; duration not tracked separately
        st.step_prepare = crate::tui::StepState::Done;
        st.step_prepare_elapsed = Some(std::time::Duration::from_millis(0));
        st.step_hub = crate::tui::StepState::Running;
        if st.step_hub_started.is_none() {
            st.step_hub_started = Some(Instant::now());
        }
    }

    let scenario_name = runner.scenario.name.clone();
    let (hub_task, _hub_port) = start_hub_task(&scenario_name);
    {
        let mut st = ui.state.lock().await;
        st.step_hub = crate::tui::StepState::Done;
        if let Some(t0) = st.step_hub_started.take() {
            st.step_hub_elapsed = Some(t0.elapsed());
        }
        st.step_metadata = crate::tui::StepState::Running;
        if st.step_metadata_started.is_none() {
            st.step_metadata_started = Some(Instant::now());
        }
    }
    let (md_task, _md_port) = start_metadata_task(&scenario_name);
    {
        let mut st = ui.state.lock().await;
        st.step_metadata = crate::tui::StepState::Done;
        if let Some(t0) = st.step_metadata_started.take() {
            st.step_metadata_elapsed = Some(t0.elapsed());
        }
        st.step_start_vms = crate::tui::StepState::Running;
        if st.step_start_vms_started.is_none() {
            st.step_start_vms_started = Some(Instant::now());
        }
        for v in st.vm_phase.values_mut() {
            *v = crate::tui::VmPhase::Starting;
        }
    }
    Ok((hub_task, md_task, scenario_name))
}

fn configure_agent_env(runner: &ScenarioRunner, scenario_name: &str) {
    // Always inject embedded agent (raw bytes), mounted via ISO in the guest.
    // Choose embedded binary by host arch (matches QEMU arch selection).
    let bytes = embedded_agent::embedded_agent_for_host();
    // Persist under scenario data dir so each VM can mount an ISO from this file
    let dirs = intar_local_backend::IntarDirs::new().expect("dirs init");
    let agent_out = dirs
        .data_scenario_dir(scenario_name)
        .join("embedded-agent")
        .join("intar-agent");
    if let Some(parent) = agent_out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Err(e) = std::fs::write(&agent_out, bytes) {
        tracing::warn!(
            "Failed to write embedded agent to {}: {}",
            agent_out.display(),
            e
        );
    } else {
        tracing::info!("Using embedded agent at: {}", agent_out.display());
        unsafe {
            std::env::set_var("INTAR_AGENT_PATH", &agent_out);
            std::env::set_var("INTAR_AGENT_FROM_ISO", "1");
        }
    }

    if let Some(ref ep) = runner.scenario.agent_otlp_endpoint {
        tracing::info!("Using agent OTLP endpoint from scenario: {ep}");
        unsafe {
            std::env::set_var("INTAR_AGENT_OTLP_ENDPOINT", ep);
        }
    }

    let sid = intar_local_backend::cloud_init::calculate_scenario_id(scenario_name);
    let md_url = format!(
        "http://10.0.2.2:{}/agent-config",
        intar_local_backend::constants::metadata_port(sid)
    );
    unsafe {
        std::env::set_var("INTAR_METADATA_URL", &md_url);
    }
}

async fn wait_for_ssh_with_ui(ui: &crate::tui::RunUi, endpoints: &[SshEndpoint]) {
    use std::collections::{HashMap, HashSet};

    let mut remaining: HashSet<String> = endpoints.iter().map(|e| e.0.clone()).collect();
    let quit_rx = ui.quit_receiver();
    let started_at = std::time::Instant::now();
    let mut attempts: HashMap<String, u32> =
        endpoints.iter().map(|e| (e.0.clone(), 0u32)).collect();

    while !remaining.is_empty() {
        if *quit_rx.borrow() {
            return;
        }
        for (vm_name, host, port, username, key_path) in endpoints.iter().cloned() {
            if remaining.contains(&vm_name) {
                // Count attempts per-VM
                if let Some(cnt) = attempts.get_mut(&vm_name) {
                    *cnt += 1;
                }
                if try_ssh_probe(ui, &vm_name, &host, port, &username, &key_path).await {
                    remaining.remove(&vm_name);
                    let elapsed = started_at.elapsed();
                    let cnt = attempts.get(&vm_name).copied().unwrap_or(0);
                    tracing::info!(
                        "ssh ready summary: vm='{}' elapsed={:.1}s attempts={}",
                        vm_name,
                        elapsed.as_secs_f32(),
                        cnt
                    );
                }
            }
        }
        if !remaining.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        }
    }
}

async fn try_ssh_probe(
    ui: &crate::tui::RunUi,
    vm_name: &str,
    host: &str,
    port: u16,
    username: &str,
    key_path: &str,
) -> bool {
    use std::process::Stdio;
    use tokio::process::Command;

    tracing::info!(
        "ssh probe: attempting {}@{}:{} for VM '{}'",
        username,
        host,
        port,
        vm_name
    );

    let mut cmd = Command::new("ssh");
    cmd.arg("-i")
        .arg(key_path)
        .arg("-p")
        .arg(port.to_string())
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("LogLevel=QUIET")
        .arg("-T")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("NumberOfPasswordPrompts=0")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
        .arg("-o")
        .arg("ConnectionAttempts=1")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg(format!("{username}@{host}"))
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Avoid ARG_MAX/E2BIG by stripping large env we set for agent embedding
    cmd.env_remove("INTAR_AGENT_BUNDLE_GZB64");
    cmd.env_remove("INTAR_AGENT_SHA256");

    match cmd.spawn() {
        Ok(mut child) => {
            match tokio::time::timeout(std::time::Duration::from_secs(6), child.wait()).await {
                Ok(Ok(status)) if status.success() => {
                    let mut st = ui.state.lock().await;
                    st.vm_phase
                        .insert(vm_name.to_string(), crate::tui::VmPhase::Ready);
                    st.vm_ssh_port.insert(vm_name.to_string(), port);
                    drop(st);
                    tracing::info!("ssh ready for {}:{}", host, port);
                    true
                }
                Ok(Ok(status)) => {
                    tracing::info!(
                        "ssh probe: non-zero exit for {}:{} (code={:?})",
                        host,
                        port,
                        status.code()
                    );
                    false
                }
                Ok(Err(e)) => {
                    tracing::info!("ssh probe: spawn/wait error for {}:{}: {}", host, port, e);
                    false
                }
                Err(_) => {
                    let _ = child.start_kill();
                    tracing::info!("ssh probe: timeout for {}:{} (killed child)", host, port);
                    false
                }
            }
        }
        Err(e) => {
            tracing::info!("ssh probe: failed to spawn for {}:{}: {}", host, port, e);
            false
        }
    }
}

async fn shutdown_phase(
    name: &str,
    ui: crate::tui::RunUi,
    runner: &mut ScenarioRunner,
    hub_task: tokio::task::JoinHandle<()>,
    md_task: tokio::task::JoinHandle<()>,
    _was_tui_quit: bool,
) -> AnyhowResult<()> {
    ui.stop().await;
    tracing::info!("Stopping all VMs in scenario: {}", name);
    if let Err(e) = runner.stop_all().await {
        tracing::error!("Error while stopping VMs: {}", e);
    }
    hub_task.abort();
    let _ = hub_task.await;
    md_task.abort();
    let _ = md_task.await;

    tracing::info!("Cleaning up scenario resources...");
    if let Err(e) = runner.cleanup_all().await {
        tracing::error!("Error while cleaning up scenario: {}", e);
    }
    tracing::info!("✓ Scenario '{}' stopped and cleaned up", name);
    Ok(())
}

async fn run_scenario(name: &str) -> AnyhowResult<()> {
    let scenario_file = find_scenario_by_name(name)?;
    let scenario = read_embedded_scenario(&scenario_file)
        .with_context(|| format!("Failed to parse scenario file: {scenario_file}"))?;

    init_file_logging_for_run(&scenario.name)?;
    let vm_names = build_vm_names(&scenario);
    let ui = create_ui(&scenario.name, &scenario.description, &vm_names);
    if let Some((q, who)) = crate::quotes::random_quote() {
        let mut st = ui.state.lock().await;
        st.quote = Some((q, who));
    }
    let mut runner = ScenarioRunner::new(scenario)?;
    populate_static_vm_info(&runner, &ui, &vm_names).await;

    // Prepare resources and start aux services (hub + metadata) with UI updates
    let (hub_task, md_task, scenario_name) = prepare_and_start_services(&mut runner, &ui).await?;

    // Configure agent-related env for backend
    configure_agent_env(&runner, &scenario_name);

    runner
        .start_all()
        .await
        .with_context(|| format!("Failed to start VMs in scenario '{name}'"))?;
    mark_vms_ready_for_ssh(&ui).await;

    // Start probes engine early so Problems panel shows immediately
    let (probe_task, probe_state) = probes::spawn_probes_engine(&runner.scenario, &vm_names);
    {
        let mut st = ui.state.lock().await;
        st.probes = Some(probe_state.clone());
    }

    // Wait for SSH readiness with UI updates
    let vm_names = sorted_vm_names(&runner);
    let endpoints = collect_ssh_endpoints(&runner, &vm_names, &scenario_name).await?;
    prepopulate_ssh_ports(&ui, &endpoints).await;
    // Wait for SSH readiness, but also honor OS Ctrl+C to stop & clean up early
    // Wait for SSH or early shutdown
    let early_shutdown = wait_for_ssh_or_signal(&ui, &endpoints, &probe_task).await;
    if early_shutdown || ui.quit_requested() {
        // Early quit during boot (OS signal or in-TUI Ctrl+C): stop and cleanup
        return shutdown_phase(name, ui, &mut runner, hub_task, md_task, true).await;
    }
    mark_ssh_done_and_complete_run(&ui).await;

    // After SSH is available, spawn background initial VM snapshots (best-effort)
    {
        let mut st = ui.state.lock().await;
        st.step_snapshot = crate::tui::StepState::Running;
        if st.step_snapshot_started.is_none() {
            st.step_snapshot_started = Some(Instant::now());
        }
    }
    spawn_initial_snapshots(&runner, &ui);

    // Probes already running; proceed to interactive wait
    let was_tui_quit = run_interactive_session(&ui, &runner, &scenario_name).await;

    // Stop probes engine task then finalize shutdown
    probe_task.abort();
    let _ = tokio::time::timeout(std::time::Duration::from_millis(200), async {
        let _ = probe_task.await;
    })
    .await;
    shutdown_phase(name, ui, &mut runner, hub_task, md_task, was_tui_quit).await
}

async fn run_interactive_session(
    ui: &crate::tui::RunUi,
    runner: &ScenarioRunner,
    scenario_name: &str,
) -> bool {
    let mut action_rx = ui.action_subscribe();
    loop {
        tokio::select! {
            () = wait_for_signal() => { return false; },
            () = ui.wait_for_quit() => { return true; },
            Ok(action) = action_rx.recv() => {
                match action {
                    crate::tui::UiAction::RestoreRequested => {
                        let mut guard = ui.state.lock().await;
                        guard.confirm_restore_active = guard.snapshot_ready;
                    }
                    crate::tui::UiAction::ConfirmRestore(yes) => {
                        let mut guard = ui.state.lock().await;
                        let do_restore = guard.confirm_restore_active && yes;
                        guard.confirm_restore_active = false;
                        if do_restore {
                            guard.restoring = true;
                        }
                        drop(guard);
                        if do_restore {
                            let restore_name = "snapshot".to_string();
                            let vm_names = sorted_vm_names(runner);
                            for vm_name in &vm_names {
                                if let Some(vm) = runner.vms.get(vm_name) {
                                    let _ = vm.snapshot_restore(&restore_name).await;
                                }
                            }
                            if let Ok(endpoints) = collect_ssh_endpoints(runner, &vm_names, scenario_name).await {
                                wait_for_ssh_with_ui(ui, &endpoints).await;
                            }
                            let mut g = ui.state.lock().await;
                            g.restoring = false;
                        }
                    }
                }
            }
            else => {}
        }
    }
}

fn spawn_initial_snapshots(runner: &ScenarioRunner, ui: &crate::tui::RunUi) {
    let scenario_name = runner.scenario.name.clone();
    let vm_names = sorted_vm_names(runner);
    let snap_name = "snapshot".to_string();
    let ui_state = ui.state.clone();
    tokio::spawn(async move {
        // Use a fresh backend instance to operate via QMP
        let backend = match intar_local_backend::LocalBackend::new() {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("Snapshot backend init failed: {}", e);
                return;
            }
        };
        // Build a minimal Scenario for state loading (only name is used)
        let minimal = intar_scenario::Scenario {
            name: scenario_name.clone(),
            description: String::new(),
            image: String::new(),
            sha256: None,
            agent_otlp_endpoint: None,
            local_agent: None,
            vm: std::collections::HashMap::new(),
            problems: indexmap::IndexMap::new(),
        };
        let mut all_ok = true;
        for vmn in vm_names {
            match backend.load_vm_from_state(vmn.clone(), &minimal).await {
                Ok(Some(vm)) => {
                    if let Err(e) = vm.snapshot_save(&snap_name).await {
                        tracing::warn!("Initial snapshot failed for {}: {}", vmn, e);
                        all_ok = false;
                    }
                }
                Ok(None) => {
                    tracing::warn!("VM not found for snapshot: {}", vmn);
                    all_ok = false;
                }
                Err(e) => {
                    tracing::warn!("Failed to open VM for snapshot {}: {}", vmn, e);
                    all_ok = false;
                }
            }
        }
        // Update UI: mark snapshot step done and show Ctrl+R only on success
        let mut g = ui_state.lock().await;
        g.step_snapshot = crate::tui::StepState::Done;
        if let Some(t0) = g.step_snapshot_started.take() {
            g.step_snapshot_elapsed = Some(t0.elapsed());
        }
        if all_ok {
            tracing::info!("Snapshot saved");
            g.snapshot_ready = true;
        } else {
            tracing::warn!("Snapshot save completed with some errors");
        }
        drop(g);
    });
}

async fn mark_vms_ready_for_ssh(ui: &crate::tui::RunUi) {
    let mut st = ui.state.lock().await;
    st.step_start_vms = crate::tui::StepState::Done;
    if let Some(t0) = st.step_start_vms_started.take() {
        st.step_start_vms_elapsed = Some(t0.elapsed());
    }
    st.step_ssh = crate::tui::StepState::Running;
    if st.step_ssh_started.is_none() {
        st.step_ssh_started = Some(Instant::now());
    }
    for v in st.vm_phase.values_mut() {
        *v = crate::tui::VmPhase::SshWait;
    }
}

async fn prepopulate_ssh_ports(ui: &crate::tui::RunUi, endpoints: &[SshEndpoint]) {
    let mut st = ui.state.lock().await;
    for (vm_name, _host, port, _user, _key) in endpoints {
        st.vm_ssh_port.insert(vm_name.clone(), *port);
    }
}

async fn wait_for_ssh_or_signal(
    ui: &crate::tui::RunUi,
    endpoints: &[SshEndpoint],
    probe_task: &tokio::task::JoinHandle<()>,
) -> bool {
    tokio::select! {
        // OS Ctrl+C (or TERM/HUP) during SSH wait: stop and clean up immediately
        () = wait_for_signal() => {
            probe_task.abort();
            true
        }
        () = wait_for_ssh_with_ui(ui, endpoints) => { false }
    }
}

async fn mark_ssh_done_and_complete_run(ui: &crate::tui::RunUi) {
    let mut st = ui.state.lock().await;
    st.step_ssh = crate::tui::StepState::Done;
    if let Some(t0) = st.step_ssh_started.take() {
        st.step_ssh_elapsed = Some(t0.elapsed());
    }
    if st.run_completed.is_none() {
        st.run_completed = Some(Instant::now());
    }
}

async fn status_scenario(name: &str) -> AnyhowResult<()> {
    let scenario_file = find_scenario_by_name(name)?;
    let scenario = read_embedded_scenario(&scenario_file)
        .with_context(|| format!("Failed to parse scenario file: {scenario_file}"))?;

    let runner = ScenarioRunner::from_state(scenario)
        .await
        .with_context(|| format!("Failed to load state for scenario '{name}'"))?;

    tracing::info!("Status for scenario '{}':", name);
    let status_map = runner
        .status_all()
        .await
        .with_context(|| format!("Failed to get status for scenario '{name}'"))?;

    if status_map.is_empty() {
        tracing::info!("  No VMs found for this scenario");
        return Ok(());
    }

    for (vm_name, status) in &status_map {
        let status_symbol = match status {
            VmStatus::Running => "🟢",
            VmStatus::Stopped => "🔴",
            VmStatus::Paused => "🟡",
            VmStatus::Unknown => "❓",
        };
        tracing::info!("  {} VM '{}': {:?}", status_symbol, vm_name, status);
    }

    // Summary
    let running_count = status_map
        .values()
        .filter(|s| matches!(s, VmStatus::Running))
        .count();
    let total_count = status_map.len();
    tracing::info!("Summary: {}/{} VMs running", running_count, total_count);

    Ok(())
}

async fn ssh_into_vm(scenario_name: &str, vm_name: &str) -> AnyhowResult<()> {
    let scenario_file = find_scenario_by_name(scenario_name)?;
    let scenario = read_embedded_scenario(&scenario_file)
        .with_context(|| format!("Failed to parse scenario file: {scenario_file}"))?;

    let runner = ScenarioRunner::from_state(scenario)
        .await
        .with_context(|| format!("Failed to load state for scenario '{scenario_name}'"))?;

    // Find the VM in the scenario
    let vm = runner.vms.get(vm_name).with_context(|| {
        format!(
            "VM '{}' not found in scenario '{}'. Available VMs: {}",
            vm_name,
            scenario_name,
            runner.vms.keys().cloned().collect::<Vec<_>>().join(", ")
        )
    })?;

    // Check if VM is running
    let status = vm
        .status()
        .await
        .with_context(|| format!("Failed to get status for VM '{vm_name}'"))?;

    if !matches!(status, VmStatus::Running) {
        bail!(
            "VM '{}' is not running (status: {:?}). Start it first with 'intar scenario run {}'",
            vm_name,
            status,
            scenario_name
        );
    }

    // Get SSH connection info
    let ssh_info = vm
        .ssh_info()
        .await
        .with_context(|| format!("Failed to get SSH info for VM '{vm_name}'"))?;

    // Require scenario SSH key path
    let key_path = ssh_info
        .private_key_path
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Scenario SSH key path not provided"))?;
    if !std::path::Path::new(&key_path).exists() {
        anyhow::bail!(
            "Scenario SSH key not found: {}. Ensure keys were generated in prepare_scenario.",
            key_path
        );
    }

    // Build SSH command
    which::which("ssh").context("'ssh' binary not found in PATH")?;
    let mut ssh_cmd = std::process::Command::new("ssh");
    ssh_cmd
        .arg("-i")
        .arg(&key_path)
        .arg("-p")
        .arg(ssh_info.port.to_string())
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("LogLevel=QUIET")
        .arg(format!(
            "{user}@{host}",
            user = ssh_info.username,
            host = ssh_info.host
        ));

    tracing::info!(
        "Connecting to VM '{}' in scenario '{}'...",
        vm_name,
        scenario_name
    );
    tracing::info!(
        "SSH command: ssh -i {} -p {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {}@{}",
        key_path,
        ssh_info.port,
        ssh_info.username,
        ssh_info.host
    );

    // Execute SSH: on Unix, replace current process; otherwise spawn and wait
    #[cfg(unix)]
    {
        let error = ssh_cmd.exec();
        Err(anyhow::anyhow!("Failed to execute SSH command: {}", error))
    }
    #[cfg(not(unix))]
    {
        let status = ssh_cmd
            .status()
            .map_err(|e| anyhow::anyhow!("Failed to launch ssh: {}", e))?;
        if status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "ssh exited with status: {:?}",
                status.code()
            ))
        }
    }
}
// probes dashboard removed
