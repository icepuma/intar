use anyhow::{Context, Result};
use futures_util::future::try_join_all;
use intar_scenario::Scenario;
use std::collections::HashMap;

use crate::IntarDirs;
use intar_local_backend::{Backend, BackendVm, LocalBackend, VmStatus};

/// Orchestrates backend operations for a scenario (prepare, start/stop, status, cleanup).
pub struct ScenarioRunner {
    pub scenario: Scenario,
    pub vms: HashMap<String, Box<dyn BackendVm>>,
    pub backend: Box<dyn Backend>,
}

impl ScenarioRunner {
    /// Create a new runner for a scenario.
    ///
    /// # Errors
    /// Returns an error if backend initialization fails.
    pub fn new(scenario: Scenario) -> Result<Self> {
        let backend = Box::new(LocalBackend::new()?);

        Ok(Self {
            scenario,
            vms: HashMap::new(),
            backend,
        })
    }

    /// Prepare the scenario (dirs, keys, images) and instantiate VMs.
    ///
    /// # Errors
    /// Returns an error if the backend fails to prepare or VMs fail to be created.
    /// Prepare the scenario (directories, keys, images) and create VMs.
    ///
    /// # Panics
    /// Panics if a VM config cannot be found for an enumerated VM name.
    ///
    /// # Errors
    /// Returns an error if backend preparation or VM creation fails.
    pub async fn prepare(&mut self) -> Result<()> {
        // Validate scenario references before any expensive work
        validate_scenario_references(&self.scenario)?;

        // Let the backend handle preparation
        self.backend
            .prepare_scenario(&self.scenario)
            .await
            .context("Backend failed to prepare scenario")?;

        // Create VMs in a deterministic order (sorted by VM name)
        let mut names: Vec<String> = self.scenario.vm.keys().cloned().collect();
        names.sort();

        for (vm_index, vm_name) in names.iter().enumerate() {
            let vm_config = self
                .scenario
                .vm
                .get(vm_name)
                .expect("VM config must exist for listed VM name");

            let vm = self
                .backend
                .create_vm(vm_name.clone(), &self.scenario, vm_config, vm_index)
                .await
                .context("Failed to create VM")?;

            self.vms.insert(vm_name.clone(), vm);
        }

        Ok(())
    }

    /// Start all VMs concurrently and wait for successful startup.
    ///
    /// # Errors
    /// Returns an error if any VM fails to start.
    pub async fn start_all(&mut self) -> Result<()> {
        if self.vms.is_empty() {
            return Ok(());
        }

        tracing::debug!(
            "Setting up cloud-init and starting {} VMs...",
            self.vms.len()
        );

        // Start all VMs concurrently (hub-based LAN removes ordering constraints)
        let mut names: Vec<String> = self.vms.keys().cloned().collect();
        names.sort();

        let start_futs = names.into_iter().filter_map(|name| {
            self.vms.get(&name).map(|vm| async move {
                tracing::debug!("Starting VM: {}", name);
                vm.start()
                    .await
                    .with_context(|| format!("Failed to start VM: {name}"))?;
                let ssh_info = vm
                    .ssh_info()
                    .await
                    .with_context(|| format!("Failed to get SSH info for VM: {name}"))?;
                tracing::debug!(
                    "VM {} started successfully with SSH access on port {}",
                    name,
                    ssh_info.port
                );
                Ok::<(), anyhow::Error>(())
            })
        });

        try_join_all(start_futs)
            .await
            .context("One or more VMs failed to start")?;

        tracing::debug!("All VMs started successfully with cloud-init SSH configuration");
        Ok(())
    }

    /// Stop all VMs concurrently.
    ///
    /// # Errors
    /// Returns an error if any VM fails to stop.
    pub async fn stop_all(&mut self) -> Result<()> {
        if self.vms.is_empty() {
            return Ok(());
        }

        tracing::debug!("Stopping {} VMs concurrently...", self.vms.len());

        // Create concurrent stop operations
        let stop_futures: Vec<_> = self
            .vms
            .iter()
            .map(|(vm_name, vm)| {
                let name = vm_name.clone();
                async move {
                    tracing::info!("Stopping VM: {}", name);
                    vm.stop()
                        .await
                        .with_context(|| format!("Failed to stop VM: {name}"))?;
                    tracing::debug!("VM {} stopped successfully", name);
                    Ok::<(), anyhow::Error>(())
                }
            })
            .collect();

        // Execute all stops concurrently
        try_join_all(stop_futures).await?;

        tracing::debug!("All VMs stopped successfully");
        Ok(())
    }

    /// Query the status of all VMs in the scenario.
    ///
    /// # Errors
    /// Returns an error if the backend fails to load VM state or query status.
    pub async fn status_all(&self) -> Result<HashMap<String, VmStatus>> {
        self.backend.get_scenario_status(&self.scenario.name).await
    }

    /// Cleanup all resources associated with the scenario (destructive).
    ///
    /// # Errors
    /// Returns an error if backend cleanup fails.
    pub async fn cleanup_all(&mut self) -> Result<()> {
        self.backend
            .cleanup_scenario(&self.scenario)
            .await
            .context("Failed to cleanup scenario")?;

        // Clear local VM references
        self.vms.clear();

        Ok(())
    }

    /// Load an existing scenario runner from persisted state.
    ///
    /// # Errors
    /// Returns an error if backend loading of VMs from state fails.
    pub async fn from_state(scenario: Scenario) -> Result<Self> {
        let mut runner = Self::new(scenario)?;

        // Load existing VMs from state
        let vm_names = runner
            .backend
            .list_scenario_vms(&runner.scenario.name)
            .await?;

        for vm_name in vm_names {
            if let Some(vm) = runner
                .backend
                .load_vm_from_state(vm_name.clone(), &runner.scenario)
                .await?
            {
                runner.vms.insert(vm_name, vm);
            }
        }

        Ok(runner)
    }
}

/// Validate that all VM-declared problem references exist in the scenario.
fn validate_scenario_references(scenario: &Scenario) -> Result<()> {
    use anyhow::bail;

    let defined_problems: std::collections::HashSet<&str> =
        scenario.problems.keys().map(String::as_str).collect();

    for (vm_name, vm) in &scenario.vm {
        for label in &vm.problems {
            if !defined_problems.contains(label.as_str()) {
                bail!(
                    "Scenario '{}' VM '{}' references unknown problem '{}'. Define it with: problem \"{}\" {{ ... }}",
                    scenario.name,
                    vm_name,
                    label,
                    label
                );
            }
        }
    }

    Ok(())
}

impl Drop for ScenarioRunner {
    fn drop(&mut self) {
        let vm_count = self.vms.len();
        if vm_count > 0 {
            let scenario = &self.scenario.name;
            tracing::warn!(
                "Scenario '{}' dropped with {} VMs potentially running.",
                scenario,
                vm_count
            );

            // Provide useful paths and next steps
            if let Ok(dirs) = IntarDirs::new() {
                let data_dir = dirs.data_scenario_dir(scenario);
                let runtime_dir = dirs.runtime_scenario_dir(scenario);
                tracing::warn!("Data dir: {}", data_dir.display());
                tracing::warn!("Runtime dir: {}", runtime_dir.display());
                tracing::warn!("Inspect status: intar scenario status {}", scenario);
            }

            // Log per‑VM hints: ssh command, PID/QMP/log locations (if present)
            let mut names: Vec<&String> = self.vms.keys().collect();
            names.sort();
            if let Ok(dirs) = IntarDirs::new() {
                for vm_name in names {
                    let pid_path = dirs.vm_pid_file(scenario, vm_name);
                    let qmp_path = dirs.vm_qmp_socket(scenario, vm_name);
                    let log_path = dirs.vm_log_file(scenario, vm_name);
                    let console_path = dirs.vm_console_log_file(scenario, vm_name);

                    // Try to read PID for convenience
                    let pid_suffix = std::fs::read_to_string(&pid_path)
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok())
                        .map(|pid| format!(" (PID: {pid})"))
                        .unwrap_or_default();

                    tracing::warn!(
                        "VM '{}' may still be running{}; ssh: intar scenario ssh {} {}",
                        vm_name,
                        pid_suffix,
                        scenario,
                        vm_name
                    );
                    tracing::warn!("  PID file: {}", pid_path.display());
                    tracing::warn!(
                        "  QMP socket: {} (echo 'quit' | socat - UNIX-CONNECT:{})",
                        qmp_path.display(),
                        qmp_path.display()
                    );
                    tracing::warn!("  Log: {}", log_path.display());
                    tracing::warn!("  Console: {}", console_path.display());
                }
            } else {
                for vm_name in self.vms.keys() {
                    tracing::warn!(
                        "VM '{}' may still be running; ssh: intar scenario ssh {} {}",
                        vm_name,
                        scenario,
                        vm_name
                    );
                }
            }
            tracing::warn!(
                "To force stop: kill the QEMU PID shown above or send QMP 'quit' to the socket."
            );
        }
    }
}
