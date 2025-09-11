use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::path::Path;
use tokio::net::UnixStream;
use tokio::time::{Duration, timeout};
use tokio_util::codec::Framed;
use uuid::Uuid;

use super::codec::QmpCodec;
use super::models::{QmpCommand, QmpGreeting, QmpResponse, StatusInfo, VmRunState};
use crate::backend::VmStatus;

fn find_filename_recursive(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(s) = map.get("file").and_then(|x| x.as_str()) {
                return Some(s.to_string());
            }
            if let Some(s) = map.get("filename").and_then(|x| x.as_str()) {
                return Some(s.to_string());
            }
            for (_k, vv) in map {
                if let Some(s) = find_filename_recursive(vv) {
                    return Some(s);
                }
            }
            None
        }
        serde_json::Value::Array(a) => {
            for vv in a {
                if let Some(s) = find_filename_recursive(vv) {
                    return Some(s);
                }
            }
            None
        }
        _ => None,
    }
}

/// Async QMP client for communicating with QEMU
pub struct QmpClient {
    framed: Framed<UnixStream, QmpCodec>,
    greeting: QmpGreeting,
}

impl QmpClient {
    fn env_timeout_ms(var: &str, default_ms: u64) -> Duration {
        std::env::var(var)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map_or_else(|| Duration::from_millis(default_ms), Duration::from_millis)
    }
    /// Connect to a QMP socket and perform handshake.
    ///
    /// # Errors
    /// Returns an error if the socket cannot be connected or if the QMP handshake fails.
    pub async fn connect(socket_path: &Path) -> Result<Self> {
        let connect_timeout = Self::env_timeout_ms("INTAR_QMP_CONNECT_TIMEOUT_MS", 10_000);

        // Connect to the Unix socket with timeout
        let stream = timeout(connect_timeout, UnixStream::connect(socket_path))
            .await
            .with_context(|| {
                format!(
                    "Connection to QMP socket timed out: {}",
                    socket_path.display()
                )
            })?
            .with_context(|| {
                format!("Failed to connect to QMP socket: {}", socket_path.display())
            })?;

        let mut framed = Framed::new(stream, QmpCodec::new());

        // Read QMP greeting
        let greeting_msg = timeout(connect_timeout, framed.next())
            .await
            .context("Timed out waiting for QMP greeting")?
            .ok_or_else(|| anyhow::anyhow!("Connection closed before receiving greeting"))?
            .context("Failed to read QMP greeting")?;

        let greeting: QmpGreeting =
            serde_json::from_value(greeting_msg).context("Failed to parse QMP greeting")?;
        tracing::info!(
            "QMP greeting: {}",
            serde_json::to_string(&greeting).unwrap_or_else(|_| "<unprintable>".to_string())
        );

        // Send qmp_capabilities command
        let capabilities_cmd = json!({
            "execute": "qmp_capabilities"
        });

        tracing::info!("QMP send: qmp_capabilities");
        framed
            .send(capabilities_cmd)
            .await
            .context("Failed to send qmp_capabilities command")?;

        // Read capabilities response
        let capabilities_response = timeout(connect_timeout, framed.next())
            .await
            .context("Timed out waiting for capabilities response")?
            .ok_or_else(|| anyhow::anyhow!("Connection closed during capabilities negotiation"))?
            .context("Failed to read capabilities response")?;

        let response: QmpResponse = serde_json::from_value(capabilities_response)
            .context("Failed to parse capabilities response")?;

        // Check if capabilities were accepted
        match response {
            QmpResponse::Success { .. } => {
                tracing::info!("QMP recv: qmp_capabilities ok");
                // Handshake successful
                Ok(Self { framed, greeting })
            }
            QmpResponse::Error { error, .. } => {
                anyhow::bail!(
                    "QMP capabilities negotiation failed: {} - {}",
                    error.class,
                    error.desc
                )
            }
        }
    }

    /// Get QMP greeting information
    pub const fn greeting(&self) -> &QmpGreeting {
        &self.greeting
    }

    /// Execute a QMP command with optional arguments.
    ///
    /// # Errors
    /// Returns an error if sending fails or if the response parsing fails.
    pub async fn execute_command(&mut self, command: &str, args: Option<Value>) -> Result<Value> {
        let command_timeout = Self::env_timeout_ms("INTAR_QMP_COMMAND_TIMEOUT_MS", 10_000);

        let id = Uuid::new_v4().to_string();
        let args_log = args
            .as_ref()
            .map_or_else(|| "{}".to_string(), std::string::ToString::to_string);
        let mut cmd = QmpCommand::new(command).with_id(id.clone());
        if let Some(a) = args.clone() {
            cmd = cmd.with_args(a);
        }

        let cmd_value = serde_json::to_value(&cmd).context("Failed to serialize QMP command")?;

        tracing::info!("QMP send id={} cmd={} args={}", id, command, args_log);
        // Send command
        self.framed
            .send(cmd_value)
            .await
            .context("Failed to send QMP command")?;

        // Read responses; filter events and unrelated replies until we get our id
        let start = std::time::Instant::now();
        loop {
            let remaining = command_timeout.saturating_sub(start.elapsed());
            let response_value = timeout(remaining, self.framed.next())
                .await
                .with_context(|| format!("Timed out waiting for response to command '{command}'"))?
                .ok_or_else(|| {
                    anyhow::anyhow!("Connection closed while waiting for command response")
                })?
                .with_context(|| format!("Failed to read response for command '{command}'"))?;

            if let Some(obj) = response_value.as_object() {
                if obj.get("event").is_some() {
                    let raw = serde_json::to_string(&response_value)
                        .unwrap_or_else(|_| "<unprintable>".to_string());
                    tracing::info!("QMP event: {}", raw);
                    continue;
                }
                if let Some(resp_id) = obj.get("id").and_then(|v| v.as_str())
                    && resp_id != id
                {
                    let raw = serde_json::to_string(&response_value)
                        .unwrap_or_else(|_| "<unprintable>".to_string());
                    tracing::info!("QMP recv unrelated: {}", raw);
                    continue;
                }
            }

            let response_text = serde_json::to_string(&response_value)
                .unwrap_or_else(|_| "<unprintable>".to_string());
            let response: QmpResponse = serde_json::from_value(response_value)
                .with_context(|| format!("Failed to parse response for command '{command}'"))?;

            match response {
                QmpResponse::Success { result, .. } => {
                    let res_log = result.to_string();
                    tracing::info!("QMP recv id={} cmd={} ok result={}", id, command, res_log);
                    return Ok(result);
                }
                QmpResponse::Error { error, .. } => {
                    tracing::info!(
                        "QMP recv id={} cmd={} error class={} desc={} raw={}",
                        id,
                        command,
                        error.class,
                        error.desc,
                        response_text
                    );
                    anyhow::bail!(
                        "QMP command '{}' failed: {} - {}",
                        command,
                        error.class,
                        error.desc
                    )
                }
            }
        }
    }

    /// Query VM status.
    ///
    /// # Errors
    /// Returns an error if the `query-status` command fails.
    pub async fn query_status(&mut self) -> Result<VmStatus> {
        let result = self
            .execute_command("query-status", None)
            .await
            .context("Failed to execute query-status command")?;

        let status_info: StatusInfo =
            serde_json::from_value(result).context("Failed to parse status response")?;

        // Convert QMP VmRunState to our VmStatus
        let vm_status = match status_info.status {
            VmRunState::Running => VmStatus::Running,
            VmRunState::Shutdown => VmStatus::Stopped,
            VmRunState::Paused | VmRunState::Debug | VmRunState::Suspended => VmStatus::Paused,
            VmRunState::Unknown => VmStatus::Unknown,
        };

        Ok(vm_status)
    }

    /// Send quit command to shutdown QEMU.
    ///
    /// # Errors
    /// Returns an error if sending the `quit` command fails.
    pub async fn quit(&mut self) -> Result<()> {
        self.execute_command("quit", None)
            .await
            .context("Failed to execute quit command")?;
        Ok(())
    }

    /// Close the QMP connection gracefully.
    ///
    /// # Errors
    /// Returns an error if the underlying framed connection cannot be closed.
    pub async fn close(mut self) -> Result<()> {
        self.framed
            .close()
            .await
            .context("Failed to close QMP connection")?;
        Ok(())
    }

    /// Execute a human monitor command (HMP) via QMP and return its textual output.
    ///
    /// # Errors
    /// Returns an error if the QMP call fails.
    pub async fn hmp_output(&mut self, command_line: &str) -> Result<String> {
        let args = json!({ "command-line": command_line });
        let val = self
            .execute_command("human-monitor-command", Some(args))
            .await
            .with_context(|| format!("Failed to execute HMP: {command_line}"))?;
        let out = val
            .as_str()
            .map_or_else(|| val.to_string(), std::string::ToString::to_string);
        Ok(out)
    }

    /// Execute a HMP command and treat certain textual outputs as errors.
    ///
    /// # Errors
    /// Returns an error if the command fails or prints an error-like message.
    pub async fn hmp(&mut self, command_line: &str) -> Result<()> {
        let out = self.hmp_output(command_line).await?;
        let low = out.to_ascii_lowercase();
        if low.contains("unknown command")
            || low.contains("error")
            || low.contains("not supported")
            || low.contains("command not found")
        {
            anyhow::bail!("HMP '{command_line}' failed: {out}");
        }
        Ok(())
    }

    /// Save a VM snapshot with the given name.
    ///
    /// Uses HMP `savevm <name>`.
    ///
    /// # Errors
    /// Returns an error if the save fails.
    pub async fn savevm(&mut self, name: &str) -> Result<()> {
        self.hmp(&format!("savevm {name}")).await
    }

    /// Load (restore) a VM snapshot with the given name.
    ///
    /// Uses HMP `loadvm <name>`.
    ///
    /// # Errors
    /// Returns an error if the restore fails.
    pub async fn loadvm(&mut self, name: &str) -> Result<()> {
        self.hmp(&format!("loadvm {name}")).await
    }

    /// Pause VM execution (equivalent to HMP `stop`).
    ///
    /// # Errors
    /// Returns an error if the stop command fails.
    pub async fn stop_vm(&mut self) -> Result<()> {
        self.hmp("stop").await
    }

    /// Resume VM execution (equivalent to HMP `cont`).
    ///
    /// # Errors
    /// Returns an error if the continue command fails.
    pub async fn cont_vm(&mut self) -> Result<()> {
        self.hmp("cont").await
    }

    /// Add a file block node.
    ///
    /// # Errors
    /// Returns an error if the QMP `blockdev-add` command fails.
    pub async fn blockdev_add_file(&mut self, node_name: &str, filename: &str) -> Result<()> {
        let args = json!({
            "node-name": node_name,
            "driver": "file",
            "filename": filename,
        });
        let _ = self
            .execute_command("blockdev-add", Some(args))
            .await
            .context("Failed to add file block node")?;
        Ok(())
    }

    /// Add a qcow2 block node wrapping a file node.
    ///
    /// # Errors
    /// Returns an error if the QMP `blockdev-add` command fails.
    pub async fn blockdev_add_qcow2(&mut self, node_name: &str, file_node: &str) -> Result<()> {
        let args = json!({
            "node-name": node_name,
            "driver": "qcow2",
            "file": file_node,
        });
        let _ = self
            .execute_command("blockdev-add", Some(args))
            .await
            .context("Failed to add qcow2 block node")?;
        Ok(())
    }

    /// Add a raw block node wrapping a file node.
    ///
    /// # Errors
    /// Returns an error if the QMP `blockdev-add` command fails.
    pub async fn blockdev_add_raw(&mut self, node_name: &str, file_node: &str) -> Result<()> {
        let args = json!({
            "node-name": node_name,
            "driver": "raw",
            "file": file_node,
        });
        let _ = self
            .execute_command("blockdev-add", Some(args))
            .await
            .context("Failed to add raw block node")?;
        Ok(())
    }

    /// Delete a block device node by name (best-effort; node must be unused).
    ///
    /// # Errors
    /// Returns an error if the QMP `blockdev-del` command fails.
    pub async fn blockdev_del(&mut self, node_name: &str) -> Result<()> {
        let args = json!({ "node-name": node_name });
        let _ = self
            .execute_command("blockdev-del", Some(args))
            .await
            .context("Failed to delete block node")?;
        Ok(())
    }

    // snapshot-save removed; we use HMP savevm instead

    // snapshot-load removed; we use HMP loadvm instead

    // snapshot-delete removed

    // job-dismiss removed

    // is_job_concluded removed

    // wait_job_concluded removed

    // job_error_string removed

    // wait_job_ok removed

    /// Return the list of named block nodes.
    ///
    /// # Errors
    /// Returns an error if the QMP query fails or returns an unexpected shape.
    pub async fn query_named_block_nodes(&mut self) -> Result<Vec<Value>> {
        let val = self
            .execute_command("query-named-block-nodes", None)
            .await
            .context("Failed to execute query-named-block-nodes")?;
        let arr = val
            .as_array()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("query-named-block-nodes did not return an array"))?;
        Ok(arr)
    }

    /// Return the list of block devices (drives) via query-block.
    ///
    /// # Errors
    /// Returns an error if the QMP query fails or returns an unexpected shape.
    pub async fn query_block(&mut self) -> Result<Vec<Value>> {
        let val = self
            .execute_command("query-block", None)
            .await
            .context("Failed to execute query-block")?;
        let arr = val
            .as_array()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("query-block did not return an array"))?;
        Ok(arr)
    }

    /// Check if a block device with the given id exists (via query-block).
    ///
    /// # Errors
    /// Returns an error if the device query fails.
    pub async fn has_block_device(&mut self, device_id: &str) -> Result<bool> {
        let devices = self.query_block().await?;
        for dev in &devices {
            if let Some(name) = dev.get("device").and_then(|v| v.as_str())
                && name == device_id
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Try to hot-add a block backend using HMP `drive_add` with if=none.
    ///
    /// # Errors
    /// Returns an error if the HMP command fails.
    /// Best-effort: returns Ok(()) if the command runs without a hard error.
    pub async fn hmp_drive_add_if_none(
        &mut self,
        device_id: &str,
        file_path: &str,
        format: &str,
    ) -> Result<()> {
        // Example HMP: drive_add 0 file=/path,if=none,format=raw,id=vmstate
        let cmd = format!("drive_add 0 file={file_path},if=none,format={format},id={device_id}");
        let out = self.hmp_output(&cmd).await?;
        // Some builds print nothing on success; log the output for diagnostics
        if !out.trim().is_empty() {
            tracing::info!("HMP drive_add output: {}", out.trim());
        }
        Ok(())
    }

    /// Find a block device (drive) id that maps to the given host file path.
    ///
    /// # Errors
    /// Returns an error if the device query fails or no device matches.
    pub async fn device_id_for_path(&mut self, path: &std::path::Path) -> Result<String> {
        let want = std::fs::canonicalize(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .to_string();
        let devices = self.query_block().await?;

        for dev in &devices {
            let dev_name = dev.get("device").and_then(|v| v.as_str()).unwrap_or("");
            let ins = dev.get("inserted");
            if dev_name.is_empty() || ins.is_none() {
                continue;
            }
            let filename = ins.and_then(find_filename_recursive).unwrap_or_default();
            if filename.is_empty() {
                continue;
            }
            let canon = std::fs::canonicalize(&filename)
                .unwrap_or_else(|_| std::path::PathBuf::from(&filename))
                .to_string_lossy()
                .to_string();
            if canon == want {
                return Ok(dev_name.to_string());
            }
        }
        anyhow::bail!(
            "No block device found for file {} (devices={})",
            want,
            serde_json::to_string(&devices).unwrap_or_default()
        )
    }

    /// Find the block node-name that ultimately backs the given host file path.
    ///
    /// # Errors
    /// Returns an error if the nodes query fails or no node matches the path.
    pub async fn node_name_for_path(&mut self, path: &std::path::Path) -> Result<String> {
        let want = std::fs::canonicalize(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .to_string();
        let nodes = self.query_named_block_nodes().await?;

        for n in &nodes {
            let filename = find_filename_recursive(n).unwrap_or_default();
            if filename.is_empty() {
                continue;
            }
            let canon = std::fs::canonicalize(&filename)
                .unwrap_or_else(|_| std::path::PathBuf::from(&filename))
                .to_string_lossy()
                .to_string();
            if canon == want {
                let node = n
                    .get("node-name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !node.is_empty() {
                    return Ok(node);
                }
            }
        }
        anyhow::bail!(
            "No block node-name maps to file {} (nodes={})",
            want,
            serde_json::to_string(&nodes).unwrap_or_default()
        )
    }

    /// Try to find the block node-name corresponding to a given device id (e.g., "disk0").
    ///
    /// # Errors
    /// Returns an error if the nodes query fails or no node matches the device id.
    pub async fn node_name_for_device(&mut self, device_id: &str) -> Result<String> {
        let nodes = self.query_named_block_nodes().await?;
        for n in &nodes {
            let dev = n.get("device").and_then(|v| v.as_str()).unwrap_or("");
            let node = n.get("node-name").and_then(|v| v.as_str()).unwrap_or("");
            if dev == device_id && !node.is_empty() {
                return Ok(node.to_string());
            }
        }
        // Fallback: if device id didn't match, try a heuristic: node-name equals device id
        for n in &nodes {
            let node = n.get("node-name").and_then(|v| v.as_str()).unwrap_or("");
            if node == device_id {
                return Ok(node.to_string());
            }
        }
        anyhow::bail!(
            "No block node found for device '{}'; nodes={}",
            device_id,
            serde_json::to_string(&nodes).unwrap_or_default()
        )
    }
}
