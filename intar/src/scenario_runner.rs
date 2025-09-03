use anyhow::{Context, Result};
use futures_util::future::try_join_all;
use intar_scenario::Scenario;
use std::collections::HashMap;

use intar_local_backend::{Backend, BackendVm, LocalBackend, VmStatus};

pub struct ScenarioRunner {
    pub scenario: Scenario,
    pub vms: HashMap<String, Box<dyn BackendVm>>,
    pub backend: Box<dyn Backend>,
}

impl ScenarioRunner {
    pub fn new(scenario: Scenario) -> Result<Self> {
        let backend = Box::new(LocalBackend::new()?);

        Ok(Self {
            scenario,
            vms: HashMap::new(),
            backend,
        })
    }

    pub async fn prepare(&mut self) -> Result<()> {
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

    pub async fn start_all(&mut self) -> Result<()> {
        if self.vms.is_empty() {
            return Ok(());
        }

        tracing::info!(
            "Setting up cloud-init and starting {} VMs...",
            self.vms.len()
        );

        // Start all VMs concurrently (hub-based LAN removes ordering constraints)
        let mut names: Vec<String> = self.vms.keys().cloned().collect();
        names.sort();

        let start_futs = names.into_iter().filter_map(|name| {
            self.vms.get(&name).map(|vm| async move {
                tracing::info!("Starting VM: {}", name);
                vm.start()
                    .await
                    .with_context(|| format!("Failed to start VM: {}", name))?;
                let ssh_info = vm
                    .ssh_info()
                    .await
                    .with_context(|| format!("Failed to get SSH info for VM: {}", name))?;
                tracing::info!(
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

        tracing::info!("All VMs started successfully with cloud-init SSH configuration");
        Ok(())
    }

    pub async fn stop_all(&mut self) -> Result<()> {
        if self.vms.is_empty() {
            return Ok(());
        }

        tracing::info!("Stopping {} VMs concurrently...", self.vms.len());

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
                        .with_context(|| format!("Failed to stop VM: {}", name))?;
                    tracing::info!("VM {} stopped successfully", name);
                    Ok::<(), anyhow::Error>(())
                }
            })
            .collect();

        // Execute all stops concurrently
        try_join_all(stop_futures).await?;

        tracing::info!("All VMs stopped successfully");
        Ok(())
    }

    pub async fn status_all(&self) -> Result<HashMap<String, VmStatus>> {
        self.backend.get_scenario_status(&self.scenario.name).await
    }

    pub async fn cleanup_all(&mut self) -> Result<()> {
        self.backend
            .cleanup_scenario(&self.scenario)
            .await
            .context("Failed to cleanup scenario")?;

        // Clear local VM references
        self.vms.clear();

        Ok(())
    }

    /// Load an existing scenario from state
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

impl Drop for ScenarioRunner {
    fn drop(&mut self) {
        let vm_count = self.vms.len();
        if vm_count > 0 {
            tracing::warn!(
                "ScenarioRunner dropped with {} VMs potentially running; ensure proper shutdown/cleanup",
                vm_count
            );
            for vm_name in self.vms.keys() {
                tracing::warn!(
                    "VM '{}' may still be running; ssh via: intar scenario ssh {} {}",
                    vm_name,
                    self.scenario.name,
                    vm_name
                );
            }
        }
    }
}
