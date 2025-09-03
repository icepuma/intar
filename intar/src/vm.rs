use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use qapi::qmp;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use tokio::fs;
use tokio::net::UnixStream;
use tokio::process::Command;

use intar_local_backend::cloud_init::{CloudInitConfig, calculate_scenario_id};
use intar_local_backend::system::QemuConfig;
use crate::dirs::IntarDirs;

/// RAII guard for QMP connections that ensures proper cleanup
struct QmpConnection {
    inner: qapi::Qmp<qapi::Stream<std::io::BufReader<StdUnixStream>, StdUnixStream>>,
}

impl QmpConnection {
    async fn connect(socket_path: &std::path::Path) -> Result<Self> {
        use qapi::{Qmp, Stream};
        use std::io::BufReader;
        use tokio::time::{Duration, timeout};

        const QMP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

        timeout(QMP_CONNECTION_TIMEOUT, async {
            let stream = UnixStream::connect(socket_path)
                .await
                .with_context(|| format!("Failed to connect to QMP socket: {}", socket_path.display()))?;

            let stream = stream
                .into_std()
                .context("Failed to convert to standard stream")?;

            let stream_clone = stream.try_clone().context("Failed to clone stream")?;
            let qapi_stream = Stream::new(BufReader::new(stream), stream_clone);
            let mut qmp = Qmp::new(qapi_stream);

            // Perform QMP handshake
            qmp.handshake().with_context(|| format!("QMP handshake failed for socket: {}", socket_path.display()))?;

            Ok::<QmpConnection, anyhow::Error>(QmpConnection { inner: qmp })
        })
        .await
        .context("QMP connection timed out")?
    }

    fn qmp(
        &mut self,
    ) -> &mut qapi::Qmp<qapi::Stream<std::io::BufReader<StdUnixStream>, StdUnixStream>> {
        &mut self.inner
    }
}

impl Drop for QmpConnection {
    fn drop(&mut self) {
        // QMP connections are automatically closed when the underlying stream is dropped
        // This serves as documentation and future extension point for cleanup logic
    }
}

// Constant error messages to avoid repeated allocations
const FAILED_TO_DETECT_QEMU: &str = "Failed to detect QEMU configuration";
const FAILED_TO_READ_VM_STATE: &str = "Failed to read VM state file";
const FAILED_TO_PARSE_VM_STATE: &str = "Failed to parse VM state JSON";
const FAILED_TO_CREATE_LOG_FILE: &str = "Failed to create log file";
const FAILED_TO_START_QEMU: &str = "Failed to start QEMU process";
const FAILED_TO_WAIT_FOR_QEMU: &str = "Failed to wait for QEMU parent process";
const FAILED_TO_SERIALIZE_STATE: &str = "Failed to serialize VM state";
const FAILED_TO_WRITE_STATE: &str = "Failed to write VM state file";
const FAILED_TO_EXECUTE_QEMU_IMG: &str = "Failed to execute qemu-img";
const FAILED_TO_CREATE_DISK_IMAGE: &str = "Failed to create disk image";
const QEMU_PARENT_PROCESS_ERROR: &str = "QEMU parent process exited with error";
const PID_FILE_NOT_CREATED: &str = "PID file was not created";
const QMP_SOCKET_NOT_AVAILABLE: &str = "QMP socket not available after 10 attempts";

#[derive(Debug, Clone)]
pub enum VmStatus {
    Stopped,
    Running,
    Paused,
    Unknown,
}

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmNetworkState {
    /// SSH port forwarding port on the host
    pub ssh_port: u16,

    /// Static IP address on the private network (eth1)
    pub static_ip: String,

    /// MAC address for eth0 (user networking interface)
    pub eth0_mac: String,

    /// MAC address for eth1 (socket networking interface)
    pub eth1_mac: String,

    /// Path to the scenario's socket file for VM-to-VM communication
    pub socket_file: String,

    /// Scenario network ID for network isolation
    pub scenario_id: u8,

    /// VM index within the scenario (for IP allocation)
    pub vm_index: u8,
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
    pub process: Option<Child>, // Only used temporarily during start

    // Network configuration
    pub network: VmNetworkState,
}

impl Vm {
    /// Create a new VM with the specified index within the scenario
    pub fn new_with_index(
        name: String,
        scenario_name: String,
        dirs: IntarDirs,
        vm_index: u8,
    ) -> Result<Self> {
        let qemu_config = QemuConfig::detect().context(FAILED_TO_DETECT_QEMU)?;

        let pid_file = dirs.vm_pid_file(&scenario_name, &name);
        let qmp_socket = dirs.vm_qmp_socket(&scenario_name, &name);
        let disk_path = dirs.vm_disk_path(&scenario_name, &name);
        let log_file = dirs.vm_log_file(&scenario_name, &name);
        let state_file = dirs.vm_state_file(&scenario_name, &name);

        // Create network configuration
        let network = Self::create_network_config(&scenario_name, &name, vm_index, &dirs);

        Ok(Self {
            name,
            scenario_name,
            dirs,
            pid_file,
            qmp_socket,
            disk_path,
            log_file,
            state_file,
            base_image: None,
            qemu_config,
            process: None,
            network,
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
        let static_ip = format!("10.{}.1.{}", scenario_id, 10 + vm_index);

        // Generate MAC addresses
        let cloud_init = CloudInitConfig::new(
            scenario_name.to_string(),
            vm_name.to_string(),
            dirs.clone(),
            String::new(), // SSH key will be set later
            vm_index,
            scenario_id,
        );
        let (eth0_mac, eth1_mac) = cloud_init.generate_mac_addresses();

        // Socket file path for scenario network
        let socket_file = dirs
            .runtime_scenario_dir(scenario_name)
            .join("network.sock")
            .to_string_lossy()
            .to_string();

        // SSH port allocation: base port 2200 + scenario_id * 10 + vm_index
        let ssh_port = 2200 + (scenario_id as u16 * 10) + (vm_index as u16);

        VmNetworkState {
            ssh_port,
            static_ip,
            eth0_mac,
            eth1_mac,
            socket_file,
            scenario_id,
            vm_index,
        }
    }

    pub async fn from_state(
        scenario_name: String,
        vm_name: String,
        dirs: IntarDirs,
    ) -> Result<Self> {
        let state_file = dirs.vm_state_file(&scenario_name, &vm_name);
        let state_content = fs::read_to_string(&state_file)
            .await
            .with_context(|| format!("{}: {}", FAILED_TO_READ_VM_STATE, state_file.display()))?;

        // Parse the state file to get network configuration
        let vm_state: VmState =
            serde_json::from_str(&state_content).context(FAILED_TO_PARSE_VM_STATE)?;

        // Reconstruct VM with network configuration from state
        let mut vm = Self::new_with_index(vm_name, scenario_name, dirs, vm_state.network.vm_index)?;

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
    pub async fn setup_cloud_init(&self, ssh_public_key: String) -> Result<PathBuf> {
        let cloud_init = CloudInitConfig::new(
            self.scenario_name.clone(),
            self.name.clone(),
            self.dirs.clone(),
            ssh_public_key,
            self.network.vm_index,
            self.network.scenario_id,
        );

        cloud_init.create_config_files().await
    }

    /// Get network information for display
    pub fn get_network_info(&self) -> String {
        format!(
            "SSH: ssh -p {} -i <key> intar@localhost\nStatic IP: {}\nScenario Network: 10.{}.1.0/24",
            self.network.ssh_port, self.network.static_ip, self.network.scenario_id
        )
    }

    /// Get SSH connection information (port, static_ip)
    pub fn get_ssh_info(&self) -> (u16, String) {
        (self.network.ssh_port, self.network.static_ip.clone())
    }

    /// Get the socket networking argument using multicast for VM-to-VM communication
    fn get_socket_netdev_arg(&self) -> String {
        // Use multicast address based on scenario ID for isolation
        // Address: 230.0.0.{scenario_id}, Port: 12340 + scenario_id
        let multicast_addr = format!("230.0.0.{}", self.network.scenario_id);
        let port = 12340 + (self.network.scenario_id as u16);

        format!("socket,id=net1,mcast={}:{}", multicast_addr, port)
    }

    /// Add cloud-init ISO drive to QEMU command
    pub async fn add_cloud_init_drive(
        &self,
        cmd: &mut Command,
        cloud_init_dir: &std::path::Path,
    ) -> Result<()> {
        // Create ISO image from cloud-init directory for better compatibility
        let iso_path = cloud_init_dir.parent().unwrap().join("cloud-init.iso");

        // Remove existing ISO file if it exists
        if iso_path.exists() {
            tokio::fs::remove_file(&iso_path).await.with_context(|| {
                format!("Failed to remove existing ISO: {}", iso_path.display())
            })?;
        }

        // Create ISO using hdiutil on macOS (genisoimage equivalent)
        // Add volume label for NoCloud datasource detection
        let output = Command::new("hdiutil")
            .args([
                "makehybrid",
                "-iso",
                "-joliet",
                "-default-volume-name",
                "cidata", // Volume label required for NoCloud
                "-o",
                &iso_path.to_string_lossy(),
                &cloud_init_dir.to_string_lossy(),
            ])
            .output()
            .await
            .context("Failed to run hdiutil to create cloud-init ISO")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to create cloud-init ISO: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Add the ISO as a CDROM drive with volume label for NoCloud detection
        cmd.args([
            "-drive",
            &format!("file={},media=cdrom,readonly=on", iso_path.display()),
        ]);

        Ok(())
    }

    /// Start VM with cloud-init configuration
    pub async fn start_with_cloud_init(&mut self, cloud_init_dir: &std::path::Path) -> Result<()> {
        self.start_internal(Some(cloud_init_dir)).await
    }

    pub async fn start(&mut self) -> Result<()> {
        self.start_internal(None).await
    }

    async fn start_internal(&mut self, cloud_init_dir: Option<&std::path::Path>) -> Result<()> {
        // Ensure all required directories exist - use a more efficient approach
        self.ensure_parent_dirs().await?;

        // Create disk image based on base image or empty
        if !self.disk_path.exists() {
            self.create_disk_image().await?;
        }

        // Build QEMU command with daemonization and dual networking
        let mut cmd = Command::new(&self.qemu_config.binary);
        cmd.args([
            "-machine",
            &self.qemu_config.machine,
            "-cpu",
            &self.qemu_config.cpu,
            "-smp",
            "2",
            "-m",
            "2G",
            // User networking for SSH access (eth0)
            "-netdev",
            &format!("user,id=net0,hostfwd=tcp::{}-:22", self.network.ssh_port),
            "-device",
            &format!("virtio-net-pci,netdev=net0,mac={}", self.network.eth0_mac),
            // Socket networking for VM-to-VM communication (eth1)
            // First VM in scenario creates socket, others connect to it
            "-netdev",
            &self.get_socket_netdev_arg(),
            "-device",
            &format!("virtio-net-pci,netdev=net1,mac={}", self.network.eth1_mac),
            "-drive",
            &format!("file={},if=virtio,format=qcow2", self.disk_path.display()),
            "-display",
            "none",
            "-daemonize", // This is the key change - daemonize the process
            "-pidfile",
            &self.pid_file.to_string_lossy(),
            "-qmp",
            &format!("unix:{},server,nowait", self.qmp_socket.display()),
        ]);

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

        println!("Starting QEMU with dual networking:");
        println!(
            "  SSH Port: {} (eth0 - user networking)",
            self.network.ssh_port
        );
        println!(
            "  Static IP: {} (eth1 - socket networking)",
            self.network.static_ip
        );
        println!("  Socket: {}", self.network.socket_file);
        println!("PID file: {}", self.pid_file.display());
        println!("QMP socket: {}", self.qmp_socket.display());
        println!("Log file: {}", self.log_file.display());

        // Create log file for stderr
        let log_file = std::fs::File::create(&self.log_file).context(FAILED_TO_CREATE_LOG_FILE)?;

        // Start QEMU - the parent process will exit when QEMU is ready
        let mut child = cmd
            .stdout(Stdio::null())
            .stderr(log_file)
            .spawn()
            .context(FAILED_TO_START_QEMU)?;

        // Wait for the parent process to exit (indicates QEMU is ready)
        let exit_status = child.wait().await.context(FAILED_TO_WAIT_FOR_QEMU)?;

        if !exit_status.success() {
            bail!("{}: {}", QEMU_PARENT_PROCESS_ERROR, exit_status);
        }

        // Process has been daemonized, so we don't hold a reference
        self.process = None;

        // Wait for PID file to be created with timeout instead of fixed sleep
        self.wait_for_pid_file().await?;

        // Save VM state
        self.save_state().await?;

        // Verify QMP socket is available
        self.wait_for_qmp_socket().await?;

        println!("VM {} started successfully and daemonized", self.name);
        Ok(())
    }

    /// Helper method to ensure all parent directories exist
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
        };

        let state_json = serde_json::to_string_pretty(&state).context(FAILED_TO_SERIALIZE_STATE)?;

        fs::write(&self.state_file, state_json)
            .await
            .with_context(|| format!("{}: {}", FAILED_TO_WRITE_STATE, self.state_file.display()))?;

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

        println!("Converting {} image to qcow2 format...", format);
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

        println!("Image converted successfully");
        Ok(qcow2_path)
    }

    /// Wait for PID file to be created with proper timeout handling
    async fn wait_for_pid_file(&self) -> Result<()> {
        use tokio::time::{Duration, Instant, sleep};

        const MAX_WAIT_TIME: Duration = Duration::from_secs(5);
        const POLL_INTERVAL: Duration = Duration::from_millis(50);

        let start_time = Instant::now();

        while start_time.elapsed() < MAX_WAIT_TIME {
            if self.pid_file.exists() {
                return Ok(());
            }
            sleep(POLL_INTERVAL).await;
        }

        bail!("{}: {}", PID_FILE_NOT_CREATED, self.pid_file.display())
    }

    async fn wait_for_qmp_socket(&self) -> Result<()> {
        use tokio::time::{Duration, Instant, sleep, timeout};

        const MAX_ATTEMPTS: u64 = 10;
        const CONNECTION_TIMEOUT: Duration = Duration::from_millis(100);
        const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

        let start_time = Instant::now();

        // Use exponential backoff with jitter for better performance under load
        for attempt in 1..=MAX_ATTEMPTS {
            // Check if we've exceeded the total timeout
            if start_time.elapsed() > TOTAL_TIMEOUT {
                break;
            }

            if self.qmp_socket.exists() {
                // Use timeout wrapper for the connection attempt
                match timeout(CONNECTION_TIMEOUT, UnixStream::connect(&self.qmp_socket)).await {
                    Ok(Ok(_stream)) => {
                        println!("QMP socket ready after {} attempts", attempt);
                        return Ok(());
                    }
                    Ok(Err(_)) | Err(_) => {
                        // Connection failed or timed out, continue to next attempt
                    }
                }
            }

            // Exponential backoff with cap: min(100ms * attempt, 1000ms)
            let backoff_duration = Duration::from_millis((100 * attempt).min(1000));
            sleep(backoff_duration).await;
        }

        bail!(QMP_SOCKET_NOT_AVAILABLE)
    }

    pub async fn stop(&mut self) -> Result<()> {
        // Try graceful shutdown via QMP first
        if self.qmp_socket.exists() && self.try_graceful_shutdown().await.is_ok() {
            println!("VM {} shut down gracefully", self.name);
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
                .with_context(|| format!("Failed to execute kill command for PID {}", pid))?;

            if status.success() {
                println!("VM {} force-stopped by PID {}", self.name, pid);
            } else {
                tracing::warn!("kill command failed for PID {}", pid);
            }
        }

        self.cleanup_files().await?;
        Ok(())
    }

    pub async fn status(&self) -> Result<VmStatus> {
        // First check if PID file exists and process is running
        match self.read_pid().await {
            Ok(pid) => {
                // Check if process is still running
                let status = Command::new("kill")
                    .args(["-0", &pid.to_string()]) // Signal 0 just checks if process exists
                    .status()
                    .await
                    .with_context(|| format!("Failed to check process status for PID {}", pid))?;

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
                eprintln!("QMP status query failed for VM {}: {}", self.name, e);
                Ok(VmStatus::Unknown) // Process exists but can't query QMP
            },
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

    async fn query_qmp_status(&self) -> Result<VmStatus> {
        use tokio::time::{Duration, timeout};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const QMP_STATUS_TIMEOUT: Duration = Duration::from_secs(10);

        timeout(QMP_STATUS_TIMEOUT, async {
            let mut stream = UnixStream::connect(&self.qmp_socket).await
                .with_context(|| format!("Failed to connect to QMP socket: {}", self.qmp_socket.display()))?;

            // Read QMP greeting
            let mut buffer = [0; 4096];
            let n = stream.read(&mut buffer).await
                .context("Failed to read QMP greeting")?;
            
            let greeting = std::str::from_utf8(&buffer[..n])
                .context("Invalid UTF-8 in QMP greeting")?;
            
            if !greeting.contains("\"QMP\"") {
                return Err(anyhow::anyhow!("Invalid QMP greeting: {}", greeting));
            }

            // Send qmp_capabilities command
            let capabilities_cmd = "{\"execute\": \"qmp_capabilities\"}\n";
            stream.write_all(capabilities_cmd.as_bytes()).await
                .context("Failed to send qmp_capabilities")?;

            // Read capabilities response
            let n = stream.read(&mut buffer).await
                .context("Failed to read capabilities response")?;
            
            let capabilities_response = std::str::from_utf8(&buffer[..n])
                .context("Invalid UTF-8 in capabilities response")?;
            
            if !capabilities_response.contains("\"return\"") {
                return Err(anyhow::anyhow!("Invalid capabilities response: {}", capabilities_response));
            }

            // Send query-status command
            let status_cmd = "{\"execute\": \"query-status\"}\n";
            stream.write_all(status_cmd.as_bytes()).await
                .context("Failed to send query-status")?;

            // Read status response
            let n = stream.read(&mut buffer).await
                .context("Failed to read status response")?;
            
            let status_response = std::str::from_utf8(&buffer[..n])
                .context("Invalid UTF-8 in status response")?;

            // Parse status from response
            if status_response.contains("\"running\": true") {
                Ok(VmStatus::Running)
            } else if status_response.contains("\"status\": \"paused\"") {
                Ok(VmStatus::Paused)
            } else if status_response.contains("\"status\": \"shutdown\"") {
                Ok(VmStatus::Stopped)
            } else {
                Ok(VmStatus::Unknown)
            }
        })
        .await
        .context("QMP status query timed out")?
    }
}

impl Vm {
    pub async fn cleanup(&mut self) -> Result<()> {
        // Full cleanup - stop VM and remove all files including data
        self.stop().await?;

        // Also remove the disk image (this is a destructive operation)
        if self.disk_path.exists() {
            fs::remove_file(&self.disk_path).await.with_context(|| {
                format!("Failed to remove disk image: {}", self.disk_path.display())
            })?;
            println!("Removed disk image for VM {}", self.name);
        }

        Ok(())
    }

    async fn try_graceful_shutdown(&self) -> Result<()> {
        use tokio::time::{Duration, timeout};

        const QMP_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

        // Use RAII guard for QMP connection management
        timeout(QMP_OPERATION_TIMEOUT, async {
            let mut qmp_conn = QmpConnection::connect(&self.qmp_socket).await?;
            qmp_conn
                .qmp()
                .execute(&qmp::quit {})
                .context("Failed to send quit command")?;
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
                .map(|pid| format!(" (PID: {})", pid))
                .unwrap_or_default();

            tracing::warn!("VM '{}' may still be running{}", self.name, pid_info);
            tracing::warn!("Use 'intar vm stop {}' to stop it", self.name);
            tracing::warn!("PID file: {}", self.pid_file.display());
        }

        // Clean up any process handle we might still hold (shouldn't happen with daemonization)
        if let Some(mut child) = self.process.take() {
            // This should not happen in normal operation due to daemonization
            let _ = child.kill();
            tracing::warn!("Cleaned up unexpected process handle for VM '{}'", self.name);
        }
    }
}
