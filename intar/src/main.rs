use anyhow::{Context, Result as AnyhowResult, bail};
use clap::{Parser, Subcommand};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use intar::VmStatus;
use intar::scenario_runner::ScenarioRunner;
use intar_scenario::{list_embedded_scenarios, read_embedded_scenario};
use std::os::unix::process::CommandExt;

#[derive(Parser)]
#[command(name = "intar")]
#[command(about = "A CLI tool for managing intar scenarios")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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

async fn run_udp_hub(_scenario: &str, port: u16) -> AnyhowResult<()> {
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    let bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
    let sock = UdpSocket::bind(bind_addr).await?;
    tracing::info!("intar hub listening on {}", bind_addr);

    let mut peers: HashSet<SocketAddr> = HashSet::new();
    let mut buf = vec![0u8; 65536];

    loop {
        let (len, src) = sock.recv_from(&mut buf).await?;
        if !peers.contains(&src) {
            peers.insert(src);
            tracing::info!("hub: new peer {} ({} total)", src, peers.len());
        }

        // Broadcast to all peers except source
        for &peer in peers.iter() {
            if peer != src {
                // Ignore errors for a peer; it might have disconnected
                let _ = sock.send_to(&buf[..len], peer).await;
            }
        }
    }
}

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
                continue;
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
        .with_context(|| format!("Failed to parse scenario file: {}", scenario_file))?;

    tracing::info!("Preparing scenario: {}", name);
    let mut runner = ScenarioRunner::new(scenario)?;

    runner
        .prepare()
        .await
        .with_context(|| format!("Failed to prepare scenario '{}'", name))?;

    // Compute hub port and start in-process UDP hub task
    let scenario_name = runner.scenario.name.clone();
    let scenario_id = intar_local_backend::cloud_init::calculate_scenario_id(&scenario_name);
    let hub_port: u16 = 18000 + (scenario_id as u16);

    tracing::info!(
        "Starting internal UDP hub for '{}' on 127.0.0.1:{}",
        scenario_name,
        hub_port
    );
    let scenario_name_for_hub = scenario_name.clone();
    let hub_task = tokio::spawn(async move {
        let _ = run_udp_hub(&scenario_name_for_hub, hub_port).await;
    });

    tracing::info!("Starting all VMs in scenario: {}", name);
    runner
        .start_all()
        .await
        .with_context(|| format!("Failed to start VMs in scenario '{}'", name))?;

    // Show progress spinners until all VMs are SSH-accessible
    let mp = MultiProgress::new();
    let spinner_style = ProgressStyle::with_template("{spinner} {msg}")
        .unwrap()
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]);

    // Build a deterministic list of VM names (sorted)
    let mut vm_names: Vec<String> = runner.vms.keys().cloned().collect();
    vm_names.sort();

    // Compute SSH endpoints deterministically (host is loopback, port is 2700 + index)
    let username = "intar".to_string();
    let dirs = intar::IntarDirs::new().context("Failed to init dirs for key path")?;
    let key_path = dirs
        .data_scenario_ssh_keys_dir(&scenario_name)
        .join("id_ed25519")
        .to_string_lossy()
        .to_string();
    if !std::path::Path::new(&key_path).exists() {
        anyhow::bail!(
            "Scenario SSH key not found: {}. Ensure keys were generated.",
            key_path
        );
    }

    // Create a spinner per VM and wait for SSH readiness (TCP connect + banner read)
    let mut tasks = Vec::new();
    for (idx, vm_name) in vm_names.clone().into_iter().enumerate() {
        let pb = mp.add(ProgressBar::new_spinner());
        pb.set_style(spinner_style.clone());
        pb.enable_steady_tick(std::time::Duration::from_millis(120));
        pb.set_message(format!("{}: waiting for SSH", vm_name));

        let host = "127.0.0.1".to_string();
        let port = intar_local_backend::constants::HOSTFWD_BASE_PORT + (idx as u16);
        let username = username.clone();
        let key_path = key_path.clone();
        tasks.push(tokio::spawn(async move {
            let timeout_total = std::time::Duration::from_secs(120);
            let start = std::time::Instant::now();
            loop {
                // Execute an actual SSH check using the system ssh client
                // Non-interactive, short connect timeout, BatchMode to avoid prompts
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
                    .arg(format!("{}@{}", username, host))
                    .arg("true")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());

                match tokio::time::timeout(std::time::Duration::from_secs(4), cmd.status()).await {
                    Ok(Ok(status)) if status.success() => {
                        pb.finish_with_message(format!(
                            "{}: SSH ready at {}:{}",
                            vm_name, host, port
                        ));
                        return Ok::<(String, u16, String, String), anyhow::Error>((
                            host, port, username, key_path,
                        ));
                    }
                    Ok(Ok(_status)) => {
                        // Not ready yet; retry
                    }
                    Ok(Err(_e)) => {
                        // Not ready yet; retry
                    }
                    Err(_) => {
                        // Not ready yet; retry
                    }
                }

                if start.elapsed() > timeout_total {
                    pb.finish_with_message(format!("{}: SSH not ready (timeout)", vm_name));
                    anyhow::bail!("VM '{}' SSH readiness timed out", vm_name);
                }

                pb.set_message(format!(
                    "{}: waiting for SSH ({}s)",
                    vm_name,
                    start.elapsed().as_secs()
                ));
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }));
    }

    // Drive progress in a separate task to keep spinners rendering
    let _mp_guard = mp.clone();

    // Collect results
    let mut ssh_map: std::collections::HashMap<String, (String, u16, String, String)> =
        std::collections::HashMap::new();
    for (i, t) in tasks.into_iter().enumerate() {
        match t.await {
            Ok(Ok((host, port, user, key))) => {
                ssh_map.insert(vm_names[i].clone(), (host, port, user, key));
            }
            Ok(Err(e)) => {
                // If any VM fails readiness, stop here
                return Err(e)
                    .with_context(|| format!("Failed waiting for SSH on VM '{}'", vm_names[i]));
            }
            Err(e) => {
                return Err(anyhow::anyhow!(e)).with_context(|| {
                    format!(
                        "Task join error while waiting for SSH on VM '{}'",
                        vm_names[i]
                    )
                });
            }
        }
    }

    // All VMs ready; keep progress lines visible (do not clear)

    // Print a concise overview
    tracing::info!("Scenario '{}' is ready. SSH + LAN details:", name);
    let scenario_id = intar_local_backend::cloud_init::calculate_scenario_id(&scenario_name);
    // Compute VM indices deterministically (sorted by name)
    let mut name_to_index = std::collections::HashMap::new();
    for (idx, n) in vm_names.iter().enumerate() {
        name_to_index.insert(n.clone(), idx as u8);
    }

    // Header
    tracing::info!("{:<10}  {:<22}  {:<12}  Key", "VM", "SSH", "LAN IP");
    tracing::info!("{:-<10}  {:-<22}  {:-<12}  {:-<20}", "", "", "", "");
    for name in &vm_names {
        if let Some((host, port, user, key)) = ssh_map.get(name) {
            let idx = *name_to_index.get(name).unwrap();
            let lan_ip = format!("172.30.{}.{}", scenario_id, 10 + idx);
            let ssh_disp = format!("{}@{}:{}", user, host, port);
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

    // Wait for termination signals
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
        .with_context(|| format!("Failed to parse scenario file: {}", scenario_file))?;

    let runner = ScenarioRunner::from_state(scenario)
        .await
        .with_context(|| format!("Failed to load state for scenario '{}'", name))?;

    tracing::info!("Status for scenario '{}':", name);
    let status_map = runner
        .status_all()
        .await
        .with_context(|| format!("Failed to get status for scenario '{}'", name))?;

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
        .with_context(|| format!("Failed to parse scenario file: {}", scenario_file))?;

    let runner = ScenarioRunner::from_state(scenario)
        .await
        .with_context(|| format!("Failed to load state for scenario '{}'", scenario_name))?;

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
        .with_context(|| format!("Failed to get status for VM '{}'", vm_name))?;

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
        .with_context(|| format!("Failed to get SSH info for VM '{}'", vm_name))?;

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
        .arg(format!("{}@{}", ssh_info.username, ssh_info.host));

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

    // Execute SSH command, replacing current process
    let error = ssh_cmd.exec();

    // If we reach this point, exec failed
    Err(anyhow::anyhow!("Failed to execute SSH command: {}", error))
}
