use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::path::Path;
use tokio::net::UnixStream;
use tokio::time::{Duration, timeout};
use tokio_util::codec::Framed;
use uuid::Uuid;

use super::codec::QmpCodec;
use super::models::*;
use crate::backend::VmStatus;

/// Async QMP client for communicating with QEMU
pub struct QmpClient {
    framed: Framed<UnixStream, QmpCodec>,
    greeting: QmpGreeting,
}

impl QmpClient {
    /// Connect to a QMP socket and perform handshake
    pub async fn connect(socket_path: &Path) -> Result<Self> {
        const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

        // Connect to the Unix socket with timeout
        let stream = timeout(CONNECT_TIMEOUT, UnixStream::connect(socket_path))
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
        let greeting_msg = timeout(CONNECT_TIMEOUT, framed.next())
            .await
            .context("Timed out waiting for QMP greeting")?
            .ok_or_else(|| anyhow::anyhow!("Connection closed before receiving greeting"))?
            .context("Failed to read QMP greeting")?;

        let greeting: QmpGreeting =
            serde_json::from_value(greeting_msg).context("Failed to parse QMP greeting")?;

        // Send qmp_capabilities command
        let capabilities_cmd = json!({
            "execute": "qmp_capabilities"
        });

        framed
            .send(capabilities_cmd)
            .await
            .context("Failed to send qmp_capabilities command")?;

        // Read capabilities response
        let capabilities_response = timeout(CONNECT_TIMEOUT, framed.next())
            .await
            .context("Timed out waiting for capabilities response")?
            .ok_or_else(|| anyhow::anyhow!("Connection closed during capabilities negotiation"))?
            .context("Failed to read capabilities response")?;

        let response: QmpResponse = serde_json::from_value(capabilities_response)
            .context("Failed to parse capabilities response")?;

        // Check if capabilities were accepted
        match response {
            QmpResponse::Success { .. } => {
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
    pub fn greeting(&self) -> &QmpGreeting {
        &self.greeting
    }

    /// Execute a QMP command with optional arguments
    pub async fn execute_command(&mut self, command: &str, args: Option<Value>) -> Result<Value> {
        const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

        let id = Uuid::new_v4().to_string();
        let cmd = QmpCommand::new(command).with_id(id.clone());
        let cmd = if let Some(args) = args {
            cmd.with_args(args)
        } else {
            cmd
        };

        let cmd_value = serde_json::to_value(&cmd).context("Failed to serialize QMP command")?;

        // Send command
        self.framed
            .send(cmd_value)
            .await
            .context("Failed to send QMP command")?;

        // Read response
        let response_value = timeout(COMMAND_TIMEOUT, self.framed.next())
            .await
            .with_context(|| format!("Timed out waiting for response to command '{}'", command))?
            .ok_or_else(|| anyhow::anyhow!("Connection closed while waiting for command response"))?
            .with_context(|| format!("Failed to read response for command '{}'", command))?;

        let response: QmpResponse = serde_json::from_value(response_value)
            .with_context(|| format!("Failed to parse response for command '{}'", command))?;

        match response {
            QmpResponse::Success { result, .. } => Ok(result),
            QmpResponse::Error { error, .. } => {
                anyhow::bail!(
                    "QMP command '{}' failed: {} - {}",
                    command,
                    error.class,
                    error.desc
                )
            }
        }
    }

    /// Query VM status
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
            VmRunState::Paused => VmStatus::Paused,
            VmRunState::Shutdown => VmStatus::Stopped,
            VmRunState::Debug => VmStatus::Paused,
            VmRunState::Suspended => VmStatus::Paused,
            VmRunState::Unknown => VmStatus::Unknown,
        };

        Ok(vm_status)
    }

    /// Send quit command to shutdown QEMU
    pub async fn quit(&mut self) -> Result<()> {
        self.execute_command("quit", None)
            .await
            .context("Failed to execute quit command")?;
        Ok(())
    }

    /// Close the QMP connection gracefully
    pub async fn close(mut self) -> Result<()> {
        self.framed
            .close()
            .await
            .context("Failed to close QMP connection")?;
        Ok(())
    }
}
