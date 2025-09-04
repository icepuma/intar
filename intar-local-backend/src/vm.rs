use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
// QMP imports are now internal
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
// Unix stream import removed - now using tokio's UnixStream via QMP client
use std::path::PathBuf;
use std::process::Stdio;
use tokio::fs;
use tokio::net::UnixStream;
use tokio::process::Command;

use crate::cloud_init::{CloudInitConfig, CloudInitSpec, calculate_scenario_id};
use crate::constants::{HOSTFWD_BASE_PORT, hub_port, lan_ip as calc_lan_ip};
use crate::dirs::IntarDirs;
use crate::system::QemuConfig;
use intar_scenario::Manipulation;

// QMP connection is now handled by our custom QMP client

// Constant error messages to avoid repeated allocations
const FAILED_TO_DETECT_QEMU: &str = "Failed to detect QEMU configuration";
const FAILED_TO_READ_VM_STATE: &str = "Failed to read VM state file";
const FAILED_TO_PARSE_VM_STATE: &str = "Failed to parse VM state JSON";
const FAILED_TO_CREATE_LOG_FILE: &str = "Failed to create log file";
const FAILED_TO_START_QEMU: &str = "Failed to start QEMU process";
const FAILED_TO_SERIALIZE_STATE: &str = "Failed to serialize VM state";
const FAILED_TO_WRITE_STATE: &str = "Failed to write VM state file";
const FAILED_TO_EXECUTE_QEMU_IMG: &str = "Failed to execute qemu-img";
const FAILED_TO_CREATE_DISK_IMAGE: &str = "Failed to create disk image";
const QMP_SOCKET_NOT_AVAILABLE: &str = "QMP socket not available after 10 attempts";

// Import VmStatus from backend module
use crate::backend::VmStatus;
use tracing::instrument;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmState {
    pub name: String,
    pub scenario_name: String,
    pub pid_file: String,
    pub qmp_socket: String,
    pub disk_path: String,
    pub log_file: String,
    pub created_at: DateTime<Utc>,

    // Network configuration
    pub network: VmNetworkState,

    // Resources
    #[serde(default = "default_cpus_state")]
    pub cpus: u8,
    #[serde(default = "default_memory_state")]
    pub memory_mb: u32,
}

const fn default_cpus_state() -> u8 {
    1
}
const fn default_memory_state() -> u32 {
    1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmNetworkState {
    /// SSH port forwarding port on the host (not needed with `socket_vmnet` but kept for compatibility)
    pub ssh_port: u16,

    /// MAC address for eth0 (single network interface)
    pub eth0_mac: String,

    /// MAC address for eth1 (private LAN interface)
    pub eth1_mac: String,

    /// Scenario network ID for network isolation
    pub scenario_id: u8,

    /// VM index within the scenario (for IP allocation)
    pub vm_index: u8,

    /// Static IP address on the private LAN (rootless socket network)
    pub lan_ip: String,

    /// TCP port used for the per-scenario socket LAN
    pub lan_port: u16,
}

pub struct Vm {
    pub name: String,
    pub scenario_name: String,
    pub dirs: IntarDirs,
    pub pid_file: PathBuf,
    pub qmp_socket: PathBuf,
    pub disk_path: PathBuf,
    pub log_file: PathBuf,
    pub state_file: PathBuf,
    pub base_image: Option<PathBuf>,
    pub qemu_config: QemuConfig,
    pub process: Option<tokio::process::Child>, // Only used temporarily during start

    // Network configuration
    pub network: VmNetworkState,

    // All VM names in the scenario for hostname resolution
    pub all_vm_names: Vec<String>,

    // Resources
    pub cpus: u8,
    pub memory_mb: u32,

    // Scenario-provided manipulation blocks for cloud-init
    pub manipulations: Vec<Manipulation>,
}

/// Configuration carrier for creating a `Vm` without an excessively long
/// constructor argument list. All fields are required.
#[derive(Clone)]
pub struct VmCreateSpec {
    /// VM name
    pub name: String,
    /// Scenario name
    pub scenario_name: String,
    /// Directory layout helper
    pub dirs: IntarDirs,
    /// VM index within the scenario
    pub vm_index: u8,
    /// All VM names in the scenario (for hosts injection)
    pub all_vm_names: Vec<String>,
    /// Number of vCPUs
    pub cpus: u8,
    /// Memory size in MB
    pub memory_mb: u32,
    /// Selected manipulations resolved from scenario definitions
    pub manipulations: Vec<Manipulation>,
}

impl Vm {
    /// Create a VM instance with its index within the scenario.
    ///
    /// # Errors
    /// Returns an error if QEMU configuration detection fails.
    pub fn new_with_spec(spec: VmCreateSpec) -> Result<Self> {
        let qemu_config = QemuConfig::detect().context(FAILED_TO_DETECT_QEMU)?;

        let pid_file = spec.dirs.vm_pid_file(&spec.scenario_name, &spec.name);
        let qmp_socket = spec.dirs.vm_qmp_socket(&spec.scenario_name, &spec.name);
        let disk_path = spec.dirs.vm_disk_path(&spec.scenario_name, &spec.name);
        let log_file = spec.dirs.vm_log_file(&spec.scenario_name, &spec.name);
        let state_file = spec.dirs.vm_state_file(&spec.scenario_name, &spec.name);

        // Create network configuration
        let network =
            Self::create_network_config(&spec.scenario_name, &spec.name, spec.vm_index, &spec.dirs);

        Ok(Self {
            name: spec.name,
            scenario_name: spec.scenario_name,
            dirs: spec.dirs,
            pid_file,
            qmp_socket,
            disk_path,
            log_file,
            state_file,
            base_image: None,
            qemu_config,
            process: None,
            network,
            all_vm_names: spec.all_vm_names,
            cpus: spec.cpus,
            memory_mb: spec.memory_mb,
            manipulations: spec.manipulations,
        })
    }

    /// Create network configuration for a VM
    fn create_network_config(
        scenario_name: &str,
        vm_name: &str,
        vm_index: u8,
        dirs: &IntarDirs,
    ) -> VmNetworkState {
        let scenario_id = calculate_scenario_id(scenario_name);

        // Generate MAC addresses
        let cloud_init = CloudInitConfig::new(CloudInitSpec {
            scenario_name: scenario_name.to_string(),
            vm_name: vm_name.to_string(),
            dirs: dirs.clone(),
            ssh_public_key: String::new(), // SSH key will be set later
            vm_index,
            scenario_id,
            all_vm_names: vec![], // VM names not available here
            manipulation_packages: vec![],
            manipulation_scripts: vec![],
        });
        let (eth0_mac, eth1_mac) = cloud_init.generate_mac_addresses();

        // SSH port allocation and LAN details via shared constants/helpers
        let ssh_port = HOSTFWD_BASE_PORT + u16::from(vm_index);
        let lan_port: u16 = hub_port(scenario_id);
        let lan_ip = calc_lan_ip(scenario_id, vm_index);

        VmNetworkState {
            ssh_port,
            eth0_mac,
            eth1_mac,
            scenario_id,
            vm_index,
            lan_ip,
            lan_port,
        }
    }

    /// Rebuild a VM object from its persisted state on disk.
    ///
    /// # Errors
    /// Returns an error if state cannot be read or parsed.
    pub async fn from_state(
        scenario_name: String,
        vm_name: String,
        dirs: IntarDirs,
    ) -> Result<Self> {
        let state_file = dirs.vm_state_file(&scenario_name, &vm_name);
        let state_content = fs::read_to_string(&state_file)
            .await
            .with_context(|| format!("{FAILED_TO_READ_VM_STATE}: {}", state_file.display()))?;

        // Parse the state file to get network configuration
        let vm_state: VmState =
            serde_json::from_str(&state_content).context(FAILED_TO_PARSE_VM_STATE)?;

        // Reconstruct VM with network configuration from state
        let mut vm = Self::new_with_spec(VmCreateSpec {
            name: vm_name,
            scenario_name,
            dirs,
            vm_index: vm_state.network.vm_index,
            all_vm_names: vec![],
            cpus: vm_state.cpus,
            memory_mb: vm_state.memory_mb,
            manipulations: Vec::new(),
        })?;

        // Restore the actual paths from saved state to ensure consistency
        vm.pid_file = PathBuf::from(&vm_state.pid_file);
        vm.qmp_socket = PathBuf::from(&vm_state.qmp_socket);
        vm.disk_path = PathBuf::from(&vm_state.disk_path);
        vm.log_file = PathBuf::from(&vm_state.log_file);

        vm.base_image = None; // Will be set externally if needed
        vm.network = vm_state.network; // Use network config from saved state

        Ok(vm)
    }

    pub fn set_base_image(&mut self, base_image: PathBuf) {
        self.base_image = Some(base_image);
    }

    /// Set up cloud-init configuration with SSH key
    #[instrument(skip(self, ssh_public_key))]
    /// Set up cloud-init configuration with the provided SSH key.
    ///
    /// # Errors
    /// Returns an error if any file operations fail.
    pub async fn setup_cloud_init(&self, ssh_public_key: String) -> Result<PathBuf> {
        // Merge packages across manipulation blocks (preserve order, dedupe)
        let mut merged_packages: Vec<String> = Vec::new();
        for m in &self.manipulations {
            for p in &m.packages {
                if !merged_packages.contains(p) {
                    merged_packages.push(p.clone());
                }
            }
        }

        // Collect scripts in declared order
        let scripts: Vec<String> = self
            .manipulations
            .iter()
            .filter_map(|m| m.script.clone())
            .collect();

        let cloud_init = CloudInitConfig::new(CloudInitSpec {
            scenario_name: self.scenario_name.clone(),
            vm_name: self.name.clone(),
            dirs: self.dirs.clone(),
            ssh_public_key,
            vm_index: self.network.vm_index,
            scenario_id: self.network.scenario_id,
            all_vm_names: self.all_vm_names.clone(),
            manipulation_packages: merged_packages,
            manipulation_scripts: scripts,
        });

        cloud_init.create_config_files().await
    }

    /// Get network information for display
    #[must_use]
    pub fn get_network_info(&self) -> String {
        format!(
            "SSH: ssh -i <key> -p {} intar@127.0.0.1\nPrivate LAN IP: {} ({})",
            self.network.ssh_port,
            self.network.lan_ip,
            crate::constants::lan_subnet(self.network.scenario_id)
        )
    }

    /// Get SSH connection information (port only - IP assigned via static config)
    #[must_use]
    pub const fn get_ssh_info(&self) -> u16 {
        self.network.ssh_port
    }

    // Removed socket_vmnet IP discovery. LAN IP is deterministic via scenario+index.

    /// Add cloud-init ISO drive to QEMU command
    ///
    /// # Panics
    /// Panics if `cloud_init_dir` has no parent directory (should not happen).
    ///
    /// # Errors
    /// Returns an error if creating or attaching the ISO image fails.
    pub async fn add_cloud_init_drive(
        &self,
        cmd: &mut Command,
        cloud_init_dir: &std::path::Path,
    ) -> Result<()> {
        let iso_path = self.create_cloud_init_iso(cloud_init_dir).await?;
        cmd.args([
            "-drive",
            &format!("file={},media=cdrom,readonly=on", iso_path.display()),
        ]);
        Ok(())
    }

    /// Create a cloud-init ISO for the given seed directory.
    ///
    /// # Errors
    /// Returns an error if ISO creation fails.
    async fn create_cloud_init_iso(
        &self,
        cloud_init_dir: &std::path::Path,
    ) -> Result<std::path::PathBuf> {
        use tokio::process::Command as TokioCommand;
        // Create ISO path
        let iso_path = cloud_init_dir.parent().unwrap().join("cloud-init.iso");
        if iso_path.exists() {
            tokio::fs::remove_file(&iso_path).await.with_context(|| {
                format!("Failed to remove existing ISO: {}", iso_path.display())
            })?;
        }

        #[cfg(target_os = "macos")]
        {
            let output = TokioCommand::new("hdiutil")
                .args([
                    "makehybrid",
                    "-iso",
                    "-joliet",
                    "-default-volume-name",
                    "cidata",
                    "-o",
                    &iso_path.to_string_lossy(),
                    &cloud_init_dir.to_string_lossy(),
                ])
                .output()
                .await
                .context("Failed to run hdiutil to create cloud-init ISO")?;
            if !output.status.success() {
                anyhow::bail!(
                    "Failed to create cloud-init ISO: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            use which::which;
            let iso_str = iso_path.to_string_lossy().to_string();
            let dir_str = cloud_init_dir.to_string_lossy().to_string();
            let (bin, args): (String, Vec<String>) = if which("genisoimage").is_ok() {
                (
                    "genisoimage".into(),
                    vec![
                        "-output".into(),
                        iso_str.clone(),
                        "-volid".into(),
                        "cidata".into(),
                        "-joliet".into(),
                        "-rock".into(),
                        dir_str.clone(),
                    ],
                )
            } else if which("mkisofs").is_ok() {
                (
                    "mkisofs".into(),
                    vec![
                        "-o".into(),
                        iso_str.clone(),
                        "-V".into(),
                        "cidata".into(),
                        "-J".into(),
                        "-r".into(),
                        dir_str.clone(),
                    ],
                )
            } else if which("xorriso").is_ok() {
                (
                    "xorriso".into(),
                    vec![
                        "-as".into(),
                        "mkisofs".into(),
                        "-V".into(),
                        "cidata".into(),
                        "-J".into(),
                        "-l".into(),
                        "-r".into(),
                        "-o".into(),
                        iso_str.clone(),
                        dir_str.clone(),
                    ],
                )
            } else {
                anyhow::bail!(
                    "No ISO creation tool found. Install one of: genisoimage, mkisofs, xorriso"
                );
            };
            let output = TokioCommand::new(&bin)
                .args(&args)
                .output()
                .await
                .with_context(|| format!("Failed to run {bin} to create cloud-init ISO"))?;
            if !output.status.success() {
                anyhow::bail!(
                    "Failed to create cloud-init ISO using {}: {}",
                    bin,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        Ok(iso_path)
    }

    /// Start VM with cloud-init configuration.
    ///
    /// # Errors
    /// Returns an error if starting QEMU fails or if the ISO cannot be attached.
    #[instrument(skip(self, cloud_init_dir))]
    pub async fn start_with_cloud_init(&mut self, cloud_init_dir: &std::path::Path) -> Result<()> {
        self.start_internal(Some(cloud_init_dir)).await
    }

    #[instrument(skip(self))]
    /// Start the VM without cloud-init.
    ///
    /// # Errors
    /// Returns an error if QEMU fails to start.
    pub async fn start(&mut self) -> Result<()> {
        self.start_internal(None).await
    }

    #[instrument(skip(self, cloud_init_dir))]
    async fn start_internal(&mut self, cloud_init_dir: Option<&std::path::Path>) -> Result<()> {
        // Ensure all required directories exist - use a more efficient approach
        self.ensure_parent_dirs().await?;

        // Create disk image based on base image or empty
        if !self.disk_path.exists() {
            self.create_disk_image().await?;
        }

        // Prepare QEMU arguments for dual-NIC rootless setup
        // NIC0: user-mode NAT with SSH port forward
        let user_netdev = format!(
            "user,id=nat0,hostfwd=tcp:127.0.0.1:{}-:22",
            self.network.ssh_port
        );
        let user_device = format!("virtio-net-pci,netdev=nat0,mac={}", self.network.eth0_mac);

        // NIC1: per-scenario LAN using UDP unicast to a local hub (rootless, N-way)
        // Each VM sends to 127.0.0.1:lan_port; hub re-broadcasts to all peers
        let lan_id = "lan0";
        let lan_netdev = format!(
            "socket,id={},udp=127.0.0.1:{},localaddr=127.0.0.1:0",
            lan_id, self.network.lan_port
        );
        let lan_device = format!(
            "virtio-net-pci,netdev={},mac={}",
            lan_id, self.network.eth1_mac
        );

        let drive_config = format!("file={},if=virtio,format=qcow2", self.disk_path.display());
        let qmp_config = format!("unix:{},server,nowait", self.qmp_socket.display());

        let mut qemu_args: Vec<String> = vec![
            "-machine".into(),
            self.qemu_config.machine.clone(),
            "-cpu".into(),
            self.qemu_config.cpu.clone(),
            "-smp".into(),
            self.cpus.to_string(),
            "-m".into(),
            format!("{}M", self.memory_mb),
            // NAT NIC for SSH and internet access
            "-netdev".into(),
            user_netdev.clone(),
            "-device".into(),
            user_device.clone(),
            // Private LAN NIC for inter-VM communication
            "-netdev".into(),
            lan_netdev.clone(),
            "-device".into(),
            lan_device.clone(),
            // Disk and control
            "-drive".into(),
            drive_config.clone(),
            "-display".into(),
            "none".into(),
            "-qmp".into(),
            qmp_config.clone(),
        ];

        // Add acceleration args if available
        qemu_args.extend(self.qemu_config.accel_args.clone());

        // Create command running QEMU directly
        let mut cmd = Command::new(&self.qemu_config.binary);
        cmd.args(&qemu_args);

        // Add cloud-init ISO drive if provided
        if let Some(cloud_init_dir) = cloud_init_dir {
            self.add_cloud_init_drive(&mut cmd, cloud_init_dir)
                .await
                .context("Failed to add cloud-init ISO drive")?;
        }

        // Add UEFI firmware if needed (for ARM64)
        if self.qemu_config.needs_uefi {
            if let Some(firmware_path) = QemuConfig::find_uefi_firmware() {
                cmd.args(["-bios", &firmware_path]);
            } else {
                tracing::warn!("UEFI firmware not found, VM may not boot properly");
            }
        }

        tracing::info!("Starting QEMU (rootless dual-NIC)");
        tracing::info!("NAT: hostfwd 127.0.0.1:{} -> 22", self.network.ssh_port);
        tracing::info!(
            "LAN: 172.30.{}.0/24 via UDP hub on 127.0.0.1:{} (localaddr ephemeral)",
            self.network.scenario_id,
            self.network.lan_port
        );
        tracing::info!("PID file: {}", self.pid_file.display());
        tracing::info!("QMP socket: {}", self.qmp_socket.display());
        tracing::info!("Log file: {}", self.log_file.display());

        // Create log file for stderr
        let log_file = std::fs::File::create(&self.log_file).context(FAILED_TO_CREATE_LOG_FILE)?;

        // Start QEMU without daemonization - we manage the process ourselves
        let child = cmd
            .stdout(Stdio::null())
            .stderr(log_file)
            .spawn()
            .context(FAILED_TO_START_QEMU)?;

        // Write PID file ourselves since we're not using -daemonize (atomic write)
        let pid = child.id().unwrap();
        let tmp_pid = self.pid_file.with_extension("pid.tmp");
        fs::write(&tmp_pid, pid.to_string())
            .await
            .context("Failed to write temporary PID file")?;
        tokio::fs::rename(&tmp_pid, &self.pid_file)
            .await
            .context("Failed to atomically persist PID file")?;

        // Store the process handle
        self.process = Some(child);

        // Save VM state
        self.save_state().await?;

        // Verify QMP socket is available
        self.wait_for_qmp_socket().await?;

        tracing::info!(
            "VM {} started successfully and running in background",
            self.name
        );
        Ok(())
    }

    /// Helper method to ensure all parent directories exist
    #[instrument(skip(self))]
    async fn ensure_parent_dirs(&self) -> Result<()> {
        // Collect all unique parent directories to avoid duplicate work
        let mut parent_dirs = HashSet::new();

        if let Some(parent) = self.disk_path.parent() {
            parent_dirs.insert(parent);
        }
        if let Some(parent) = self.pid_file.parent() {
            parent_dirs.insert(parent);
        }
        if let Some(parent) = self.qmp_socket.parent() {
            parent_dirs.insert(parent);
        }
        if let Some(parent) = self.log_file.parent() {
            parent_dirs.insert(parent);
        }
        if let Some(parent) = self.state_file.parent() {
            parent_dirs.insert(parent);
        }

        // Create all unique directories
        for parent_dir in parent_dirs {
            self.dirs.ensure_dir(&parent_dir.to_path_buf()).await?;
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn create_disk_image(&self) -> Result<()> {
        let mut create_cmd = Command::new("qemu-img");

        if let Some(base_image) = &self.base_image {
            // First, detect and potentially convert the base image
            let base_image_qcow2 = self.ensure_qcow2_image(base_image).await?;

            // Create a COW overlay on the base image
            create_cmd
                .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
                .arg(&base_image_qcow2)
                .arg(&self.disk_path);
        } else {
            // Create empty disk
            create_cmd
                .args(["create", "-f", "qcow2"])
                .arg(&self.disk_path)
                .arg("10G");
        }

        let status = create_cmd.status().await.with_context(|| {
            format!(
                "{} for disk: {}",
                FAILED_TO_EXECUTE_QEMU_IMG,
                self.disk_path.display()
            )
        })?;

        if !status.success() {
            bail!(FAILED_TO_CREATE_DISK_IMAGE);
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn save_state(&self) -> Result<()> {
        let state = VmState {
            name: self.name.clone(),
            scenario_name: self.scenario_name.clone(),
            // Use Box<str> to avoid the double conversion and allocation
            pid_file: self.pid_file.to_string_lossy().into_owned(),
            qmp_socket: self.qmp_socket.to_string_lossy().into_owned(),
            disk_path: self.disk_path.to_string_lossy().into_owned(),
            log_file: self.log_file.to_string_lossy().into_owned(),
            created_at: Utc::now(),
            network: self.network.clone(),
            cpus: self.cpus,
            memory_mb: self.memory_mb,
        };

        let state_json = serde_json::to_string_pretty(&state).context(FAILED_TO_SERIALIZE_STATE)?;

        fs::write(&self.state_file, state_json)
            .await
            .with_context(|| format!("{FAILED_TO_WRITE_STATE}: {}", self.state_file.display()))?;

        Ok(())
    }

    async fn ensure_qcow2_image(&self, image_path: &std::path::Path) -> Result<PathBuf> {
        // Check if image is already qcow2
        let info_output = Command::new("qemu-img")
            .args(["info", "--output", "json"])
            .arg(image_path)
            .output()
            .await
            .with_context(|| format!("Failed to get image info for: {}", image_path.display()))?;

        if !info_output.status.success() {
            bail!("Failed to get image info");
        }

        let info: serde_json::Value = serde_json::from_slice(&info_output.stdout)
            .context("Failed to parse qemu-img info JSON")?;

        let format = info
            .get("format")
            .and_then(|f| f.as_str())
            .unwrap_or("unknown");

        if format == "qcow2" {
            return Ok(image_path.to_path_buf());
        }

        // Convert to qcow2
        let qcow2_path = image_path.with_extension("qcow2");

        tracing::info!("Converting {} image to qcow2 format...", format);
        let convert_status = Command::new("qemu-img")
            .args(["convert", "-f", format, "-O", "qcow2"])
            .arg(image_path)
            .arg(&qcow2_path)
            .status()
            .await
            .with_context(|| {
                format!(
                    "Failed to convert image from {} to qcow2: {} -> {}",
                    format,
                    image_path.display(),
                    qcow2_path.display()
                )
            })?;

        if !convert_status.success() {
            bail!("Failed to convert image to qcow2");
        }

        tracing::info!("Image converted successfully");
        Ok(qcow2_path)
    }

    #[instrument(skip(self))]
    async fn wait_for_qmp_socket(&self) -> Result<()> {
        use tokio::time::{Duration, Instant, sleep, timeout};

        const MAX_ATTEMPTS: u64 = 120; // ~30s total
        const CONNECTION_TIMEOUT: Duration = Duration::from_millis(200);
        const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

        let start_time = Instant::now();

        // Use exponential backoff with jitter for better performance under load
        for attempt in 1..=MAX_ATTEMPTS {
            // Check if we've exceeded the total timeout
            if start_time.elapsed() > TOTAL_TIMEOUT {
                break;
            }

            if self.qmp_socket.exists() {
                // Use timeout wrapper for the connection attempt
                if let Ok(Ok(_stream)) =
                    timeout(CONNECTION_TIMEOUT, UnixStream::connect(&self.qmp_socket)).await
                {
                    tracing::info!("QMP socket ready after {} attempts", attempt);
                    return Ok(());
                }
                // Connection failed or timed out, continue to next attempt
            }

            // Exponential backoff with cap: min(250ms * attempt, 1000ms)
            let backoff_duration = Duration::from_millis((250 * attempt).min(1000));
            sleep(backoff_duration).await;
        }

        bail!(
            "{} (VM: {}). Check log: {}",
            QMP_SOCKET_NOT_AVAILABLE,
            self.name,
            self.log_file.display()
        )
    }

    #[instrument(skip(self))]
    /// Stop the VM gracefully via QMP, falling back to kill by PID.
    ///
    /// # Errors
    /// Returns an error if process operations fail.
    pub async fn stop(&mut self) -> Result<()> {
        // Try graceful shutdown via QMP first
        if self.qmp_socket.exists() && self.try_graceful_shutdown().await.is_ok() {
            tracing::info!("VM {} shut down gracefully", self.name);
            self.cleanup_files().await?;
            return Ok(());
        }

        // Read PID and force kill if graceful shutdown failed
        if let Ok(pid) = self.read_pid().await {
            // Kill by PID
            let status = Command::new("kill")
                .arg(pid.to_string())
                .status()
                .await
                .with_context(|| format!("Failed to execute kill command for PID {pid}"))?;

            if status.success() {
                tracing::warn!("VM {} force-stopped by PID {}", self.name, pid);
            } else {
                tracing::warn!("kill command failed for PID {}", pid);
            }
        }

        self.cleanup_files().await?;
        Ok(())
    }

    #[instrument(skip(self))]
    /// Query the VM status using PID and QMP.
    ///
    /// # Errors
    /// Returns an error if the PID check or QMP call fails unexpectedly.
    pub async fn status(&self) -> Result<VmStatus> {
        // First check if PID file exists and process is running
        match self.read_pid().await {
            Ok(pid) => {
                // Check if process is still running
                let status = Command::new("kill")
                    .args(["-0", &pid.to_string()]) // Signal 0 just checks if process exists
                    .status()
                    .await
                    .with_context(|| format!("Failed to check process status for PID {pid}"))?;

                if !status.success() {
                    return Ok(VmStatus::Stopped);
                }
            }
            Err(_) => return Ok(VmStatus::Stopped),
        }

        // If process exists, try to get detailed status via QMP
        if !self.qmp_socket.exists() {
            return Ok(VmStatus::Unknown);
        }

        match self.query_qmp_status().await {
            Ok(status) => Ok(status),
            Err(e) => {
                tracing::warn!("QMP status query failed for VM {}: {}", self.name, e);
                Ok(VmStatus::Unknown) // Process exists but can't query QMP
            }
        }
    }

    async fn read_pid(&self) -> Result<u32> {
        let pid_content = fs::read_to_string(&self.pid_file)
            .await
            .with_context(|| format!("Failed to read PID file: {}", self.pid_file.display()))?;

        pid_content.trim().parse::<u32>().with_context(|| {
            format!(
                "Invalid PID '{}' in file: {}",
                pid_content.trim(),
                self.pid_file.display()
            )
        })
    }

    async fn cleanup_files(&self) -> Result<()> {
        // Clean up runtime files
        if self.pid_file.exists() {
            let _ = fs::remove_file(&self.pid_file).await;
        }
        if self.qmp_socket.exists() {
            let _ = fs::remove_file(&self.qmp_socket).await;
        }

        // Remove state file
        if self.state_file.exists() {
            let _ = fs::remove_file(&self.state_file).await;
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn query_qmp_status(&self) -> Result<VmStatus> {
        use crate::qmp::QmpClient;

        let mut client = QmpClient::connect(&self.qmp_socket)
            .await
            .with_context(|| {
                format!(
                    "Failed to connect to QMP socket: {}",
                    self.qmp_socket.display()
                )
            })?;

        let status = client
            .query_status()
            .await
            .context("Failed to query VM status via QMP")?;

        // Close the connection gracefully
        let _ = client.close().await;

        Ok(status)
    }
}

impl Vm {
    #[instrument(skip(self))]
    /// Stop the VM (if running) and remove its data.
    ///
    /// # Errors
    /// Returns an error if stopping or removing files fails.
    pub async fn cleanup(&mut self) -> Result<()> {
        // Full cleanup - stop VM and remove all files including data
        self.stop().await?;

        // Also remove the disk image (this is a destructive operation)
        if self.disk_path.exists() {
            fs::remove_file(&self.disk_path).await.with_context(|| {
                format!("Failed to remove disk image: {}", self.disk_path.display())
            })?;
            tracing::info!("Removed disk image for VM {}", self.name);
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn try_graceful_shutdown(&self) -> Result<()> {
        use crate::qmp::QmpClient;
        use tokio::time::{Duration, timeout};

        const QMP_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

        timeout(QMP_OPERATION_TIMEOUT, async {
            let mut client = QmpClient::connect(&self.qmp_socket)
                .await
                .context("Failed to connect to QMP socket for shutdown")?;

            client.quit().await.context("Failed to send quit command")?;

            // Connection will be closed automatically when client is dropped
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("QMP graceful shutdown timed out")?
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        // RAII cleanup for VM resources
        // DO NOT kill processes - they should persist as daemons

        // Check if VM is still running and provide helpful information
        if let Ok(metadata) = std::fs::metadata(&self.pid_file)
            && metadata.is_file()
        {
            // Try to read PID for more informative message
            let pid_info = std::fs::read_to_string(&self.pid_file)
                .ok()
                .and_then(|content| content.trim().parse::<u32>().ok())
                .map(|pid| format!(" (PID: {pid})"))
                .unwrap_or_default();

            tracing::warn!("VM '{}' may still be running{}", self.name, pid_info);
            tracing::warn!("Use 'intar vm stop {}' to stop it", self.name);
            tracing::warn!("PID file: {}", self.pid_file.display());
        }

        // Clean up any process handle we might still hold (shouldn't happen with daemonization)
        if let Some(mut child) = self.process.take() {
            // This should not happen in normal operation due to daemonization
            let _ = child.start_kill();
            tracing::warn!(
                "Cleaned up unexpected process handle for VM '{}'",
                self.name
            );
        }
    }
}

// BackendVm trait is now implemented by VmWrapper in backend.rs
