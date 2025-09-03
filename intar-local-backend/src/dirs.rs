use anyhow::{Context, Result};
use directories::ProjectDirs;
use futures_util::future::try_join_all;
use std::path::{Path, PathBuf};

// Constant path components to avoid repeated allocations
const IMAGES_DIR: &str = "images";
const SCENARIOS_DIR: &str = "scenarios";
const VMS_DIR: &str = "vms";
const SSH_KEYS_DIR: &str = "ssh-keys";
const VM_DISK_FILENAME: &str = "disk.qcow2";
const VM_STATE_FILENAME: &str = "state.json";
const VM_PID_FILENAME: &str = "vm.pid";
const VM_QMP_FILENAME: &str = "vm.qmp";
const VM_LOG_FILENAME: &str = "vm.log";

#[derive(Debug, Clone)]
pub struct IntarDirs {
    project_dirs: ProjectDirs,
}

impl IntarDirs {
    pub fn new() -> Result<Self> {
        let project_dirs = ProjectDirs::from("", "", "intar")
            .ok_or_else(|| anyhow::anyhow!("Failed to determine project directories"))?;

        Ok(Self { project_dirs })
    }

    /// Cache directory for downloaded base images (can be cleared)
    /// ~/.cache/intar/images/
    pub fn cache_images_dir(&self) -> PathBuf {
        self.project_dirs.cache_dir().join(IMAGES_DIR)
    }

    /// Data directory for persistent VM data
    /// ~/.local/share/intar/scenarios/
    pub fn data_scenarios_dir(&self) -> PathBuf {
        self.project_dirs.data_dir().join(SCENARIOS_DIR)
    }

    /// Data directory for a specific scenario
    /// ~/.local/share/intar/scenarios/{scenario}/
    pub fn data_scenario_dir(&self, scenario: &str) -> PathBuf {
        self.data_scenarios_dir().join(scenario)
    }

    /// Data directory for VMs in a scenario  
    /// ~/.local/share/intar/scenarios/{scenario}/vms/
    pub fn data_scenario_vms_dir(&self, scenario: &str) -> PathBuf {
        self.data_scenario_dir(scenario).join(VMS_DIR)
    }

    /// Data directory for a specific VM disk
    /// ~/.local/share/intar/scenarios/{scenario}/vms/{vm}/
    pub fn data_vm_dir(&self, scenario: &str, vm: &str) -> PathBuf {
        self.data_scenario_vms_dir(scenario).join(vm)
    }

    /// SSH keys directory for a scenario
    /// ~/.local/share/intar/scenarios/{scenario}/ssh-keys/
    pub fn data_scenario_ssh_keys_dir(&self, scenario: &str) -> PathBuf {
        self.data_scenario_dir(scenario).join(SSH_KEYS_DIR)
    }

    /// State directory for VM state files
    /// ~/.local/state/intar/scenarios/ (or fallback to data dir)
    pub fn state_scenarios_dir(&self) -> PathBuf {
        let base = self
            .project_dirs
            .state_dir()
            .unwrap_or(self.project_dirs.data_dir());
        base.join(SCENARIOS_DIR)
    }

    /// State directory for a specific scenario
    /// ~/.local/state/intar/scenarios/{scenario}/
    pub fn state_scenario_dir(&self, scenario: &str) -> PathBuf {
        self.state_scenarios_dir().join(scenario)
    }

    /// State directory for a specific VM
    /// ~/.local/state/intar/scenarios/{scenario}/vms/{vm}/
    pub fn state_vm_dir(&self, scenario: &str, vm: &str) -> PathBuf {
        self.state_scenario_dir(scenario).join(VMS_DIR).join(vm)
    }

    /// Runtime directory for temporary files (sockets, PIDs)
    /// /run/user/{uid}/intar/scenarios/ (Linux) or fallback to data dir
    pub fn runtime_scenarios_dir(&self) -> PathBuf {
        let base = self
            .project_dirs
            .runtime_dir()
            .unwrap_or(self.project_dirs.data_dir());
        base.join(SCENARIOS_DIR)
    }

    /// Runtime directory for a specific scenario
    /// /run/user/{uid}/intar/scenarios/{scenario}/
    pub fn runtime_scenario_dir(&self, scenario: &str) -> PathBuf {
        self.runtime_scenarios_dir().join(scenario)
    }

    /// Runtime directory for a specific VM
    /// /run/user/{uid}/intar/scenarios/{scenario}/vms/{vm}/
    pub fn runtime_vm_dir(&self, scenario: &str, vm: &str) -> PathBuf {
        self.runtime_scenario_dir(scenario).join(VMS_DIR).join(vm)
    }

    /// Get path for a cached base image
    /// ~/.cache/intar/images/{filename}
    pub fn cached_image_path(&self, filename: &str) -> PathBuf {
        self.cache_images_dir().join(filename)
    }

    /// Get path for a VM disk image
    /// ~/.local/share/intar/scenarios/{scenario}/{vm}/disk.qcow2
    pub fn vm_disk_path(&self, scenario: &str, vm: &str) -> PathBuf {
        self.data_vm_dir(scenario, vm).join(VM_DISK_FILENAME)
    }

    /// Get path for VM state JSON file
    /// ~/.local/state/intar/scenarios/{scenario}/{vm}/state.json
    pub fn vm_state_file(&self, scenario: &str, vm: &str) -> PathBuf {
        self.state_vm_dir(scenario, vm).join(VM_STATE_FILENAME)
    }

    /// Get path for VM PID file
    /// /run/user/{uid}/intar/scenarios/{scenario}/{vm}/vm.pid
    pub fn vm_pid_file(&self, scenario: &str, vm: &str) -> PathBuf {
        self.runtime_vm_dir(scenario, vm).join(VM_PID_FILENAME)
    }

    /// Get path for VM QMP socket
    /// /run/user/{uid}/intar/scenarios/{scenario}/{vm}/vm.qmp
    pub fn vm_qmp_socket(&self, scenario: &str, vm: &str) -> PathBuf {
        self.runtime_vm_dir(scenario, vm).join(VM_QMP_FILENAME)
    }

    /// Get path for VM log file
    /// /run/user/{uid}/intar/scenarios/{scenario}/{vm}/vm.log
    pub fn vm_log_file(&self, scenario: &str, vm: &str) -> PathBuf {
        self.runtime_vm_dir(scenario, vm).join(VM_LOG_FILENAME)
    }

    // No separate hub process; foreground mode runs the hub in-process.

    /// Ensure a directory exists, creating it and all parents if necessary
    pub async fn ensure_dir<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        tokio::fs::create_dir_all(path)
            .await
            .with_context(|| format!("Failed to create directory: {}", path.display()))?;
        Ok(())
    }

    /// Initialize all required directories for intar
    pub async fn init(&self) -> Result<()> {
        // Collect all directories to create to avoid repeated method calls
        let dirs_to_create = [
            self.cache_images_dir(),
            self.data_scenarios_dir(),
            self.state_scenarios_dir(),
            self.runtime_scenarios_dir(),
        ];

        // Create all directories concurrently for better performance
        let create_futures = dirs_to_create.iter().map(|dir| self.ensure_dir(dir));
        try_join_all(create_futures).await?;

        Ok(())
    }
}

// tests removed
