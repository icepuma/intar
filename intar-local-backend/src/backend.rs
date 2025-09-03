use anyhow::{Context, Result};
use async_trait::async_trait;
use intar_scenario::{Scenario, VmConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::instrument;

/// VM status that is backend-agnostic
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VmStatus {
    Running,
    Stopped,
    Paused,
    Unknown,
}

impl std::fmt::Display for VmStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmStatus::Running => write!(f, "🟢 Running"),
            VmStatus::Stopped => write!(f, "🔴 Stopped"),
            VmStatus::Paused => write!(f, "🟡 Paused"),
            VmStatus::Unknown => write!(f, "❓ Unknown"),
        }
    }
}

/// SSH connection information for a VM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshInfo {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub private_key_path: Option<String>,
}

/// Backend-agnostic VM interface
/// Note: Using Arc<Mutex<T>> or similar for interior mutability when implementing
#[async_trait]
pub trait BackendVm: Send + Sync {
    /// Get the VM name
    async fn name(&self) -> String;

    /// Get the scenario name this VM belongs to
    async fn scenario_name(&self) -> String;

    /// Start the VM
    async fn start(&self) -> Result<()>;

    /// Stop the VM gracefully
    async fn stop(&self) -> Result<()>;

    /// Get current VM status
    async fn status(&self) -> Result<VmStatus>;

    /// Get SSH connection information
    async fn ssh_info(&self) -> Result<SshInfo>;

    /// Cleanup VM resources (destructive)
    async fn cleanup(&self) -> Result<()>;
}

/// Backend interface for managing VM scenarios
#[async_trait]
pub trait Backend: Send + Sync {
    /// Get the backend name/type
    fn name(&self) -> &'static str;

    /// Prepare the backend for running a scenario
    /// This includes downloading images, setting up directories, etc.
    async fn prepare_scenario(&self, scenario: &Scenario) -> Result<()>;

    /// Create a new VM instance based on the scenario and VM config
    async fn create_vm(
        &self,
        vm_name: String,
        scenario: &Scenario,
        config: &VmConfig,
        vm_index: usize,
    ) -> Result<Box<dyn BackendVm>>;

    /// Load an existing VM from persistent state
    async fn load_vm_from_state(
        &self,
        vm_name: String,
        scenario: &Scenario,
    ) -> Result<Option<Box<dyn BackendVm>>>;

    /// List all VMs for a scenario
    async fn list_scenario_vms(&self, scenario_name: &str) -> Result<Vec<String>>;

    /// Get VM status for all VMs in a scenario
    async fn get_scenario_status(&self, scenario_name: &str) -> Result<HashMap<String, VmStatus>>;

    /// Stop all VMs in a scenario
    async fn stop_scenario(&self, scenario_name: &str) -> Result<()>;

    /// Cleanup all resources for a scenario (destructive)
    async fn cleanup_scenario(&self, scenario: &Scenario) -> Result<()>;
}

/// Local QEMU-based backend implementation
pub struct LocalBackend {
    dirs: crate::dirs::IntarDirs,
}

impl LocalBackend {
    pub fn new() -> Result<Self> {
        let dirs = crate::dirs::IntarDirs::new().context("Failed to initialize IntarDirs")?;

        Ok(Self { dirs })
    }
}

#[async_trait]
#[async_trait]
impl Backend for LocalBackend {
    fn name(&self) -> &'static str {
        "local"
    }

    #[instrument(skip(self), fields(scenario = %scenario.name))]
    async fn prepare_scenario(&self, scenario: &Scenario) -> Result<()> {
        use crate::ssh::SshKeyManager;
        use futures_util::StreamExt;
        use tokio::fs::File;
        use tokio::io::AsyncWriteExt;

        // Initialize all required directories
        self.dirs
            .init()
            .await
            .context("Failed to initialize intar directories")?;

        // Generate SSH keys for this scenario
        let ssh_manager = SshKeyManager::new(scenario.name.clone(), self.dirs.clone());
        ssh_manager
            .ensure_keys()
            .await
            .context("Failed to generate SSH keys for scenario")?;

        // Download base image if it doesn't exist
        let image_filename = scenario
            .image
            .split('/')
            .next_back()
            .unwrap_or("base-image")
            .to_string();

        let image_filename = if image_filename.contains('.') {
            image_filename
        } else {
            format!("{}.qcow2", image_filename)
        };

        let image_path = self.dirs.cached_image_path(&image_filename);

        if !image_path.exists() {
            tracing::info!("Downloading base image: {}", scenario.image);
            let response = reqwest::get(&scenario.image)
                .await
                .with_context(|| format!("Failed to download image from {}", scenario.image))?;

            if !response.status().is_success() {
                anyhow::bail!("Failed to download image: HTTP {}", response.status());
            }

            // Ensure parent directory exists
            if let Some(parent) = image_path.parent() {
                self.dirs
                    .ensure_dir(parent)
                    .await
                    .context("Failed to create image cache directory")?;
            }

            let mut file = File::create(&image_path).await.with_context(|| {
                format!("Failed to create image file: {}", image_path.display())
            })?;

            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.context("Failed to download image chunk")?;
                file.write_all(&chunk)
                    .await
                    .context("Failed to write image data")?;
            }

            tracing::info!("Base image downloaded: {}", image_path.display());
        }

        Ok(())
    }

    #[instrument(skip(self, scenario, _config))]
    async fn create_vm(
        &self,
        vm_name: String,
        scenario: &Scenario,
        _config: &VmConfig,
        vm_index: usize,
    ) -> Result<Box<dyn BackendVm>> {
        use crate::vm::Vm;

        // Extract all VM names from the scenario in deterministic order (sorted)
        let mut all_vm_names: Vec<String> = scenario.vm.keys().cloned().collect();
        all_vm_names.sort();

        let mut vm = Vm::new_with_index(
            vm_name,
            scenario.name.clone(),
            self.dirs.clone(),
            vm_index as u8,
            all_vm_names,
        )
        .context("Failed to create VM")?;

        // Set the base image from the scenario
        let image_filename = scenario
            .image
            .split('/')
            .next_back()
            .unwrap_or("base-image")
            .to_string();

        let image_filename = if image_filename.contains('.') {
            image_filename
        } else {
            format!("{}.qcow2", image_filename)
        };

        let image_path = self.dirs.cached_image_path(&image_filename);
        vm.set_base_image(image_path);

        Ok(Box::new(VmWrapper {
            inner: Arc::new(Mutex::new(vm)),
        }))
    }

    #[instrument(skip(self, scenario))]
    async fn load_vm_from_state(
        &self,
        vm_name: String,
        scenario: &Scenario,
    ) -> Result<Option<Box<dyn BackendVm>>> {
        use crate::vm::Vm;

        match Vm::from_state(scenario.name.clone(), vm_name.clone(), self.dirs.clone()).await {
            Ok(vm) => Ok(Some(Box::new(VmWrapper {
                inner: Arc::new(Mutex::new(vm)),
            }))),
            Err(_e) => {
                Ok(None) // VM doesn't exist in state
            }
        }
    }

    #[instrument(skip(self))]
    async fn list_scenario_vms(&self, scenario_name: &str) -> Result<Vec<String>> {
        use tokio::fs;

        let vms_dir = self.dirs.data_scenario_vms_dir(scenario_name);

        if !vms_dir.exists() {
            return Ok(Vec::new());
        }

        let mut vms = Vec::new();
        let mut entries = fs::read_dir(&vms_dir)
            .await
            .with_context(|| format!("Failed to read VMs directory: {}", vms_dir.display()))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .context("Failed to read directory entry")?
        {
            let file_name = entry.file_name();

            if entry
                .file_type()
                .await
                .context("Failed to get file type")?
                .is_dir()
                && let Some(vm_name) = file_name.to_str()
            {
                vms.push(vm_name.to_string());
            }
        }

        Ok(vms)
    }

    #[instrument(skip(self))]
    async fn get_scenario_status(&self, scenario_name: &str) -> Result<HashMap<String, VmStatus>> {
        let vm_names = self.list_scenario_vms(scenario_name).await?;
        let mut status_map = HashMap::new();

        for vm_name in vm_names {
            if let Some(vm) = self
                .load_vm_from_state(
                    vm_name.clone(),
                    &Scenario {
                        name: scenario_name.to_string(),
                        description: String::new(),
                        image: String::new(), // These fields aren't used for loading state
                        vm: HashMap::new(),
                    },
                )
                .await?
            {
                let status = vm.status().await.unwrap_or(VmStatus::Unknown);
                status_map.insert(vm_name, status);
            }
        }

        Ok(status_map)
    }

    #[instrument(skip(self))]
    async fn stop_scenario(&self, scenario_name: &str) -> Result<()> {
        let vm_names = self.list_scenario_vms(scenario_name).await?;

        for vm_name in vm_names {
            if let Some(vm) = self
                .load_vm_from_state(
                    vm_name.clone(),
                    &Scenario {
                        name: scenario_name.to_string(),
                        description: String::new(),
                        image: String::new(),
                        vm: HashMap::new(),
                    },
                )
                .await?
                && let Err(e) = vm.stop().await
            {
                tracing::warn!("Failed to stop VM {}: {}", vm_name, e);
            }
        }

        Ok(())
    }

    #[instrument(skip(self, scenario))]
    async fn cleanup_scenario(&self, scenario: &Scenario) -> Result<()> {
        // Stop all VMs first
        self.stop_scenario(&scenario.name).await?;

        // Remove all scenario directories
        let directories_to_remove = vec![
            self.dirs.data_scenario_dir(&scenario.name),
            self.dirs.state_scenario_dir(&scenario.name),
            self.dirs.runtime_scenario_dir(&scenario.name),
        ];

        for dir_path in directories_to_remove {
            if dir_path.exists() {
                match tokio::fs::remove_dir_all(&dir_path).await {
                    Ok(()) => {
                        tracing::info!("Removed scenario directory: {}", dir_path.display());
                    }
                    Err(e) => {
                        tracing::warn!("Failed to remove directory {}: {}", dir_path.display(), e);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Wrapper for Vm that provides interior mutability for BackendVm trait
pub struct VmWrapper {
    inner: Arc<Mutex<crate::vm::Vm>>,
}

#[async_trait]
impl BackendVm for VmWrapper {
    async fn name(&self) -> String {
        let vm = self.inner.lock().await;
        vm.name.clone()
    }

    async fn scenario_name(&self) -> String {
        let vm = self.inner.lock().await;
        vm.scenario_name.clone()
    }

    async fn start(&self) -> Result<()> {
        use crate::ssh::SshKeyManager;

        let mut vm = self.inner.lock().await;

        // Set up SSH key manager to get the public key
        let ssh_manager = SshKeyManager::new(vm.scenario_name.clone(), vm.dirs.clone());
        let public_key = ssh_manager
            .read_public_key()
            .await
            .context("Failed to read SSH public key for VM startup")?;

        // Set up cloud-init configuration with SSH key
        let cloud_init_dir = vm
            .setup_cloud_init(public_key)
            .await
            .context("Failed to set up cloud-init configuration")?;

        // Start VM with cloud-init
        vm.start_with_cloud_init(&cloud_init_dir).await
    }

    async fn stop(&self) -> Result<()> {
        let mut vm = self.inner.lock().await;
        vm.stop().await
    }

    async fn status(&self) -> Result<VmStatus> {
        let vm = self.inner.lock().await;
        vm.status().await
    }

    async fn ssh_info(&self) -> Result<SshInfo> {
        let vm = self.inner.lock().await;

        // Rootless mode: always SSH via localhost port forwarding
        let host = "127.0.0.1".to_string();
        let port = vm.network.ssh_port;

        Ok(SshInfo {
            host,
            port,
            username: "intar".to_string(), // Default cloud-init user
            private_key_path: Some(
                vm.dirs
                    .data_scenario_ssh_keys_dir(&vm.scenario_name)
                    .join("id_ed25519")
                    .to_string_lossy()
                    .to_string(),
            ),
        })
    }

    async fn cleanup(&self) -> Result<()> {
        let mut vm = self.inner.lock().await;
        vm.cleanup().await
    }
}
