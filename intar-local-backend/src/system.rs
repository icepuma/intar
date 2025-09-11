use anyhow::{Context, Result};
use std::env;
use std::sync::OnceLock;
use which::which;

// Static cache for UEFI firmware path to avoid repeated filesystem checks
static UEFI_FIRMWARE_PATH: OnceLock<Option<String>> = OnceLock::new();

// Constant firmware paths to avoid repeated allocations
const FIRMWARE_PATHS: &[&str] = &[
    // macOS with Homebrew (most common first for faster lookup)
    "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
    "/usr/local/share/qemu/edk2-aarch64-code.fd",
    // Linux (common distributions)
    "/usr/share/AAVMF/AAVMF_CODE.fd",
    "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
    "/usr/share/edk2/aarch64/QEMU_EFI.fd",
    "/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw",
    "/usr/share/edk2-ovmf/aarch64/OVMF_CODE.fd",
    "/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw",
    "/usr/share/qemu/qemu_efi.fd",
    "/usr/share/qemu/edk2-arm-code.fd",
];

// Architecture-specific constants to avoid repeated allocations
const X86_64_MACHINE: &str = "q35";
const ARM64_MACHINE: &str = "virt";
const MAX_CPU: &str = "max";

#[derive(Debug, Clone)]
pub struct QemuConfig {
    pub binary: String,
    pub machine: String,
    pub cpu: String,
    pub needs_uefi: bool,
    pub accel_args: Vec<String>,
}

// Cache for detected QEMU config to avoid repeated detection
static DETECTED_QEMU_CONFIG: OnceLock<Result<QemuConfig, String>> = OnceLock::new();

impl QemuConfig {
    #[inline]
    /// Detect QEMU configuration for the current host.
    ///
    /// # Errors
    /// Returns an error if the QEMU binary cannot be found or the architecture is unsupported.
    pub fn detect() -> Result<Self> {
        // Use cached result if available
        DETECTED_QEMU_CONFIG
            .get_or_init(|| {
                let arch = env::consts::ARCH;
                Self::for_architecture(arch).map_err(|e| e.to_string())
            })
            .clone()
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    /// Build a QEMU configuration for the given architecture.
    ///
    /// # Errors
    /// Returns an error if binaries are not found or architecture is unsupported.
    pub fn for_architecture(arch: &str) -> Result<Self> {
        let os = std::env::consts::OS;
        let mut cfg = match arch {
            "x86_64" => Self {
                binary: Self::find_qemu_binary("qemu-system-x86_64")?,
                machine: X86_64_MACHINE.to_string(),
                cpu: MAX_CPU.to_string(),
                needs_uefi: false,
                accel_args: Vec::new(),
            },
            "aarch64" => Self {
                binary: Self::find_qemu_binary("qemu-system-aarch64")?,
                machine: ARM64_MACHINE.to_string(),
                cpu: MAX_CPU.to_string(),
                needs_uefi: true,
                accel_args: Vec::new(),
            },
            other => anyhow::bail!("Unsupported architecture: {}", other),
        };

        // OS-specific acceleration (overridable via env)
        match os {
            "macos" => {
                cfg.accel_args = vec!["-accel".to_string(), "hvf".to_string()];
            }
            "linux" => {
                cfg.accel_args = vec!["-enable-kvm".to_string()];
                cfg.cpu = "host".to_string();
            }
            _ => {}
        }

        // Allow explicit override: INTAR_ACCEL=tcg|hvf|kvm|none (useful to enable savevm/loadvm)
        if let Ok(accel) = env::var("INTAR_ACCEL") {
            let a = accel.to_ascii_lowercase();
            cfg.accel_args = match a.as_str() {
                "tcg" => vec!["-accel".to_string(), "tcg".to_string()],
                "hvf" => vec!["-accel".to_string(), "hvf".to_string()],
                "kvm" => vec!["-enable-kvm".to_string()],
                "none" => Vec::new(),
                other => {
                    tracing::warn!("Unknown INTAR_ACCEL='{}', keeping default accel", other);
                    cfg.accel_args.clone()
                }
            };
        } else if env::var("INTAR_FORCE_TCG")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        {
            cfg.accel_args = vec!["-accel".to_string(), "tcg".to_string()];
        }

        Ok(cfg)
    }

    /// Find a QEMU system binary in PATH.
    ///
    /// # Errors
    /// Returns an error if the binary is not present in PATH.
    fn find_qemu_binary(binary_name: &str) -> Result<String> {
        which(binary_name)
            .with_context(|| format!("{binary_name} not found in PATH"))?
            .to_string_lossy()
            .to_string()
            .pipe(Ok)
    }

    pub fn find_uefi_firmware() -> Option<String> {
        // Use cached result if available to avoid repeated filesystem checks
        UEFI_FIRMWARE_PATH
            .get_or_init(|| {
                // Check common locations for UEFI firmware
                FIRMWARE_PATHS
                    .iter()
                    .find(|&&path| std::path::Path::new(path).exists())
                    .map(|&path| path.to_string())
            })
            .clone()
    }
}

// Helper trait for better ergonomics with performance hints
trait Pipe<T> {
    fn pipe<F, U>(self, f: F) -> U
    where
        F: FnOnce(Self) -> U,
        Self: Sized;
}

impl<T> Pipe<T> for T {
    #[inline]
    fn pipe<F, U>(self, f: F) -> U
    where
        F: FnOnce(Self) -> U,
    {
        f(self)
    }
}

// tests removed
