use anyhow::{Context, Result};
use rand;
use ssh_key::{Algorithm, PrivateKey};
use std::path::PathBuf;
use tokio::fs;

use crate::dirs::IntarDirs;

const SSH_KEY_COMMENT_PREFIX: &str = "intar-scenario";

pub struct SshKeyManager {
    scenario_name: String,
    dirs: IntarDirs,
}

impl SshKeyManager {
    pub fn new(scenario_name: String, dirs: IntarDirs) -> Self {
        Self {
            scenario_name,
            dirs,
        }
    }

    /// Get the paths where SSH keys should be stored for this scenario
    pub fn get_key_paths(&self) -> (PathBuf, PathBuf) {
        let key_dir = self
            .dirs
            .data_scenario_dir(&self.scenario_name)
            .join("ssh-keys");
        let private_key_path = key_dir.join("id_ed25519");
        let public_key_path = key_dir.join("id_ed25519.pub");
        (private_key_path, public_key_path)
    }

    /// Check if SSH keys already exist for this scenario
    pub async fn keys_exist(&self) -> bool {
        let (private_path, public_path) = self.get_key_paths();
        private_path.exists() && public_path.exists()
    }

    /// Generate new ed25519 SSH keypair for this scenario
    pub async fn generate_keypair(&self) -> Result<()> {
        if self.keys_exist().await {
            return Ok(()); // Keys already exist, no need to generate
        }

        let (private_path, public_path) = self.get_key_paths();

        // Ensure the key directory exists
        if let Some(key_dir) = private_path.parent() {
            self.dirs
                .ensure_dir(key_dir)
                .await
                .context("Failed to create SSH key directory")?;
        }

        // Generate ED25519 key pair
        let mut private_key = PrivateKey::random(&mut rand::thread_rng(), Algorithm::Ed25519)
            .context("Failed to generate Ed25519 private key")?;

        // Set comment for the key
        let comment = format!("{}-{}", SSH_KEY_COMMENT_PREFIX, self.scenario_name);
        private_key.set_comment(&comment);

        // Get public key
        let public_key = private_key.public_key();

        // Convert to OpenSSH format
        let private_key_data = private_key
            .to_openssh(ssh_key::LineEnding::LF)
            .context("Failed to serialize private key to OpenSSH format")?;
        let public_key_data = public_key
            .to_openssh()
            .context("Failed to serialize public key to OpenSSH format")?;

        // Save private key with proper permissions (600)
        fs::write(&private_path, private_key_data)
            .await
            .with_context(|| {
                format!("Failed to write private key to {}", private_path.display())
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&private_path)
                .await
                .context("Failed to get private key file metadata")?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&private_path, perms)
                .await
                .context("Failed to set private key file permissions")?;
        }

        // Save public key (644 permissions are fine)
        fs::write(&public_path, public_key_data)
            .await
            .with_context(|| format!("Failed to write public key to {}", public_path.display()))?;

        println!("Generated SSH keypair for scenario: {}", self.scenario_name);
        println!("  Private key: {}", private_path.display());
        println!("  Public key: {}", public_path.display());

        Ok(())
    }

    /// Read the public key content for inclusion in cloud-init
    pub async fn read_public_key(&self) -> Result<String> {
        let (_, public_path) = self.get_key_paths();

        if !public_path.exists() {
            anyhow::bail!(
                "Public key does not exist for scenario '{}'. Generate keys first.",
                self.scenario_name
            );
        }

        let public_key = fs::read_to_string(&public_path)
            .await
            .with_context(|| format!("Failed to read public key from {}", public_path.display()))?;

        Ok(public_key.trim().to_string())
    }

    /// Get the private key path for SSH client usage
    pub fn get_private_key_path(&self) -> PathBuf {
        let (private_path, _) = self.get_key_paths();
        private_path
    }

    /// Ensure SSH keys exist, generating them if needed
    pub async fn ensure_keys(&self) -> Result<()> {
        if !self.keys_exist().await {
            self.generate_keypair().await?;
        }
        Ok(())
    }

    /// Remove SSH keys for this scenario (used during cleanup)
    pub async fn cleanup_keys(&self) -> Result<()> {
        let (private_path, public_path) = self.get_key_paths();

        if private_path.exists() {
            fs::remove_file(&private_path).await.with_context(|| {
                format!("Failed to remove private key: {}", private_path.display())
            })?;
        }

        if public_path.exists() {
            fs::remove_file(&public_path).await.with_context(|| {
                format!("Failed to remove public key: {}", public_path.display())
            })?;
        }

        // Remove the SSH keys directory if it's empty
        if let Some(key_dir) = private_path.parent()
            && key_dir.exists()
        {
            match fs::remove_dir(key_dir).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                    // Directory not empty, that's fine
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("Failed to remove SSH key directory: {}", key_dir.display())
                    });
                }
            }
        }

        Ok(())
    }
}
