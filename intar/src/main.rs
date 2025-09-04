use anyhow::{Context, Result as AnyhowResult, bail};
use clap::{Parser, Subcommand};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use intar::VmStatus;
use intar::scenario_runner::ScenarioRunner;
use intar_scenario::{list_embedded_scenarios, read_embedded_scenario};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[derive(Parser)]
#[command(name = "intar")]
#[command(about = "A CLI tool for managing intar scenarios")]
#[command(version)]
#[command(
    after_help = "Examples:\n  intar scenario list\n  intar scenario run MultiDemo\n  intar scenario status MultiDemo\n  intar scenario ssh MultiDemo web\n"
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

fn build_spinner_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner} {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_spinner())
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
}

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

fn sorted_vm_names(runner: &ScenarioRunner) -> Vec<String> {
    let mut names: Vec<String> = runner.vms.keys().cloned().collect();
    names.sort();
    names
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

async fn wait_for_all_ssh(
    mp: &MultiProgress,
    style: &ProgressStyle,
    endpoints: Vec<SshEndpoint>,
    scenario_name: &str,
) -> AnyhowResult<std::collections::HashMap<String, (String, u16, String, String)>> {
    let mut tasks = Vec::with_capacity(endpoints.len());
    for (vm_name, host, port, username, key_path) in endpoints.clone() {
        let pb = mp.add(ProgressBar::new_spinner());
        pb.set_style(style.clone());
        pb.enable_steady_tick(std::time::Duration::from_millis(120));
        pb.set_message(format!("{vm_name}: waiting for SSH"));
        tasks.push(tokio::spawn(async move {
            let timeout_total = std::time::Duration::from_secs(120);
            let start = std::time::Instant::now();
            loop {
                use std::process::Stdio;
                use tokio::process::Command;
                let mut cmd = Command::new("ssh");
                cmd.arg("-i")
                    .arg(&key_path)
                    .arg("-p")
                    .arg(port.to_string())
                    .arg("-o")
                    .arg("StrictHostKeyChecking=no")
                    .arg("-o")
                    .arg("UserKnownHostsFile=/dev/null")
                    .arg("-o")
                    .arg("GlobalKnownHostsFile=/dev/null")
                    .arg("-o")
                    .arg("LogLevel=ERROR")
                    .arg("-o")
                    .arg("BatchMode=yes")
                    .arg("-o")
                    .arg("ConnectTimeout=3")
                    .arg(format!("{username}@{host}"))
                    .arg("true")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());

                match tokio::time::timeout(std::time::Duration::from_secs(4), cmd.status()).await {
                    Ok(Ok(status)) if status.success() => {
                        pb.finish_with_message(format!("{vm_name}: SSH ready at {host}:{port}"));
                        return Ok::<(String, u16, String, String), anyhow::Error>((
                            host, port, username, key_path,
                        ));
                    }
                    _ => {}
                }

                if start.elapsed() > timeout_total {
                    pb.finish_with_message(format!("{vm_name}: SSH not ready (timeout)"));
                    anyhow::bail!("VM '{vm_name}' SSH readiness timed out");
                }

                pb.set_message(format!(
                    "{vm_name}: waiting for SSH ({}s)",
                    start.elapsed().as_secs()
                ));
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }));
    }

    let mut ssh_map: std::collections::HashMap<String, (String, u16, String, String)> =
        std::collections::HashMap::new();
    for (i, t) in tasks.into_iter().enumerate() {
        match t.await {
            Ok(Ok((host, port, user, key))) => {
                ssh_map.insert(endpoints[i].0.clone(), (host, port, user, key));
            }
            Ok(Err(e)) => {
                let log_hint = intar::IntarDirs::new()
                    .ok()
                    .map_or("<unknown>".to_string(), |d| {
                        d.vm_log_file(scenario_name, &endpoints[i].0)
                            .display()
                            .to_string()
                    });
                return Err(e).with_context(|| {
                    format!(
                        "Failed waiting for SSH on VM '{}'. Check log: {log_hint}",
                        endpoints[i].0
                    )
                });
            }
            Err(e) => {
                return Err(anyhow::anyhow!(e)).with_context(|| {
                    format!(
                        "Task join error while waiting for SSH on VM '{}'",
                        endpoints[i].0
                    )
                });
            }
        }
    }
    Ok(ssh_map)
}

fn print_overview(
    scenario_name: &str,
    vm_names: &[String],
    ssh_map: &std::collections::HashMap<String, (String, u16, String, String)>,
) {
    tracing::info!("Scenario '{}' is ready. SSH + LAN details:", scenario_name);
    let scenario_id = intar_local_backend::cloud_init::calculate_scenario_id(scenario_name);
    tracing::info!("{:<10}  {:<22}  {:<12}  Key", "VM", "SSH", "LAN IP");
    tracing::info!("{:-<10}  {:-<22}  {:-<12}  {:-<20}", "", "", "", "");
    for (idx, name) in vm_names.iter().enumerate() {
        if let Some((host, port, user, key)) = ssh_map.get(name) {
            let idx_u8 = u8::try_from(idx).unwrap_or(u8::MAX);
            let lan_ip = intar_local_backend::constants::lan_ip(scenario_id, idx_u8);
            let ssh_disp = format!("{user}@{host}:{port}");
            let key_disp = key.as_str();
            tracing::info!(
                "{:<10}  {:<22}  {:<12}  {}",
                name,
                ssh_disp,
                lan_ip,
                key_disp
            );
        }
    }
    tracing::info!("Press Ctrl+C to stop and cleanly shutdown all VMs.");
}

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
    // Initialize tracing subscriber with env-based filter (default info), compact format
    use tracing_subscriber::{EnvFilter, fmt};
    let _ = fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .try_init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scenario { action } => match action {
            ScenarioCommands::List => {
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
                status_scenario(&name).await?;
            }
            ScenarioCommands::Ssh { scenario, vm } => {
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

async fn run_scenario(name: &str) -> AnyhowResult<()> {
    let scenario_file = find_scenario_by_name(name)?;
    let scenario = read_embedded_scenario(&scenario_file)
        .with_context(|| format!("Failed to parse scenario file: {scenario_file}"))?;

    tracing::info!("Preparing scenario: {}", name);
    let mut runner = ScenarioRunner::new(scenario)?;

    runner
        .prepare()
        .await
        .with_context(|| format!("Failed to prepare scenario '{name}'"))?;

    // Compute hub port and start in-process UDP hub task
    let scenario_name = runner.scenario.name.clone();
    let (hub_task, _hub_port) = start_hub_task(&scenario_name);

    tracing::info!("Starting all VMs in scenario: {}", name);
    runner
        .start_all()
        .await
        .with_context(|| format!("Failed to start VMs in scenario '{name}'"))?;

    // Wait for SSH readiness and show overview
    let mp = MultiProgress::new();
    let spinner_style = build_spinner_style();
    let vm_names = sorted_vm_names(&runner);
    let endpoints = collect_ssh_endpoints(&runner, &vm_names, &scenario_name).await?;
    let _mp_guard = mp.clone();
    let ssh_map = wait_for_all_ssh(&mp, &spinner_style, endpoints, &scenario_name).await?;
    print_overview(&scenario_name, &vm_names, &ssh_map);

    wait_for_signal().await;

    tracing::info!("Stopping all VMs in scenario: {}", name);
    if let Err(e) = runner.stop_all().await {
        tracing::error!("Error while stopping VMs: {}", e);
    }

    // Stop hub task
    hub_task.abort();
    let _ = hub_task.await; // ignore abort error

    tracing::info!("Cleaning up scenario resources...");
    if let Err(e) = runner.cleanup_all().await {
        tracing::error!("Error while cleaning up scenario: {}", e);
    }

    tracing::info!("✓ Scenario '{}' stopped and cleaned up", name);
    Ok(())
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
