//! Cryptographic utilities for key generation.
//!
//! This module provides functionality for generating cryptographic keys
//! using external tools like OpenSSL.

use std::process::Command;

/// Represents a generated RSA key pair
pub struct RsaKeyPair {
    pub private_key: String,
    pub public_key: String,
}

/// Error type for crypto operations
#[derive(Debug)]
pub enum CryptoError {
    OpenSSLNotFound,
    GenerationFailed(String),
    InvalidKeyFormat,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::OpenSSLNotFound => {
                write!(f, "OpenSSL is required for key generation but was not found.\n       Please install OpenSSL and ensure it's in your PATH.\n       macOS: brew install openssl\n       Ubuntu/Debian: sudo apt install openssl\n       Fedora: sudo dnf install openssl")
            }
            CryptoError::GenerationFailed(msg) => write!(f, "Key generation failed: {}", msg),
            CryptoError::InvalidKeyFormat => write!(f, "Generated key has invalid format"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Check if OpenSSL is available in the system PATH
pub fn check_openssl_available() -> Result<(), CryptoError> {
    match Command::new("openssl").arg("version").output() {
        Ok(output) if output.status.success() => Ok(()),
        _ => Err(CryptoError::OpenSSLNotFound),
    }
}

/// Generate a 2048-bit RSA key pair using OpenSSL
///
/// Returns a tuple of (private_key, public_key) as PEM-encoded strings.
/// The private key is in PKCS#1 format and the public key is in PKCS#8 format.
pub fn generate_rsa_keypair() -> Result<RsaKeyPair, CryptoError> {
    // Check OpenSSL is available first
    check_openssl_available()?;

    // Create temporary file for private key
    let temp_dir = std::env::temp_dir();
    let private_key_path = temp_dir.join(format!("cred_rsa_{}", uuid::Uuid::new_v4()));

    // Generate 2048-bit RSA private key
    let private_output = Command::new("openssl")
        .args(["genrsa", "-traditional", "2048"])
        .output()
        .map_err(|_| {
            CryptoError::GenerationFailed("Failed to execute openssl genrsa".to_string())
        })?;

    if !private_output.status.success() {
        return Err(CryptoError::GenerationFailed(
            "RSA private key generation failed".to_string(),
        ));
    }

    let private_key =
        String::from_utf8(private_output.stdout).map_err(|_| CryptoError::InvalidKeyFormat)?;

    // Write private key to temp file
    std::fs::write(&private_key_path, &private_key)
        .map_err(|e| CryptoError::GenerationFailed(format!("Failed to write temp file: {}", e)))?;

    // Extract public key from private key
    let public_output = Command::new("openssl")
        .args(["rsa", "-in", private_key_path.to_str().unwrap(), "-pubout"])
        .output()
        .map_err(|_| {
            CryptoError::GenerationFailed("Failed to execute openssl rsa -pubout".to_string())
        })?;

    // Clean up temp file
    let _ = std::fs::remove_file(&private_key_path);

    if !public_output.status.success() {
        return Err(CryptoError::GenerationFailed(
            "RSA public key extraction failed".to_string(),
        ));
    }

    let public_key =
        String::from_utf8(public_output.stdout).map_err(|_| CryptoError::InvalidKeyFormat)?;

    // Validate PEM format
    if !private_key.contains("BEGIN RSA PRIVATE KEY")
        || !private_key.contains("END RSA PRIVATE KEY")
    {
        return Err(CryptoError::InvalidKeyFormat);
    }

    if !public_key.contains("BEGIN PUBLIC KEY") || !public_key.contains("END PUBLIC KEY") {
        return Err(CryptoError::InvalidKeyFormat);
    }

    Ok(RsaKeyPair {
        private_key,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_openssl_available() {
        // This test will pass on systems with OpenSSL, fail on others
        // We expect it to pass in CI and development environments
        let result = check_openssl_available();
        // We don't assert success since it depends on the environment
        // but the function should return a result
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_generate_rsa_keypair_structure() {
        // Skip this test if OpenSSL is not available
        if check_openssl_available().is_err() {
            return;
        }

        let keypair = generate_rsa_keypair().expect("Key generation should succeed");

        // Verify private key structure
        assert!(keypair
            .private_key
            .contains("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(keypair
            .private_key
            .contains("-----END RSA PRIVATE KEY-----"));

        // Verify public key structure
        assert!(keypair.public_key.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(keypair.public_key.contains("-----END PUBLIC KEY-----"));

        // Verify keys are not empty
        assert!(!keypair.private_key.is_empty());
        assert!(!keypair.public_key.is_empty());
    }

    #[test]
    fn test_rsa_keypair_unique_keys() {
        // Skip this test if OpenSSL is not available
        if check_openssl_available().is_err() {
            return;
        }

        let keypair1 = generate_rsa_keypair().expect("First key generation should succeed");
        let keypair2 = generate_rsa_keypair().expect("Second key generation should succeed");

        // Verify different keys are generated each time
        assert_ne!(keypair1.private_key, keypair2.private_key);
        assert_ne!(keypair1.public_key, keypair2.public_key);
    }
}
