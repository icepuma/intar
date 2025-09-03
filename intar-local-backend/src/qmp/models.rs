use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// QMP greeting message received upon connection
#[derive(Debug, Serialize, Deserialize)]
pub struct QmpGreeting {
    #[serde(rename = "QMP")]
    pub qmp: QmpVersionInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QmpVersionInfo {
    pub version: QmpVersion,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QmpVersion {
    pub qemu: QemuVersion,
    pub package: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QemuVersion {
    pub major: u32,
    pub minor: u32,
    pub micro: u32,
}

/// QMP command structure
#[derive(Debug, Serialize, Deserialize)]
pub struct QmpCommand {
    pub execute: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl QmpCommand {
    pub fn new(command: &str) -> Self {
        Self {
            execute: command.to_string(),
            arguments: None,
            id: None,
        }
    }

    pub fn with_id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    pub fn with_args(mut self, args: Value) -> Self {
        self.arguments = Some(args);
        self
    }
}

/// QMP response structure
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QmpResponse {
    Success {
        #[serde(rename = "return")]
        result: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    Error {
        error: QmpError,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QmpError {
    pub class: String,
    pub desc: String,
}

/// VM run state as returned by query-status command
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmRunState {
    Running,
    Paused,
    Shutdown,
    Debug,
    Suspended,
    #[serde(other)]
    Unknown,
}

/// Response from query-status command
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusInfo {
    pub status: VmRunState,
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub singlestep: Option<bool>,
}

/// QMP event structure (for future use)
#[derive(Debug, Serialize, Deserialize)]
pub struct QmpEvent {
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<HashMap<String, Value>>,
    pub timestamp: QmpTimestamp,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QmpTimestamp {
    pub seconds: u64,
    pub microseconds: u64,
}
