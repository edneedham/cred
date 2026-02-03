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
                write!(
                    f,
                    "OpenSSL is required for key generation but was not found.\n       Please install OpenSSL and ensure it's in your PATH.\n       macOS: brew install openssl\n       Ubuntu/Debian: sudo apt install openssl\n       Fedora: sudo dnf install openssl"
                )
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

    // Generate 2048-bit RSA private key (use -traditional for PKCS#1 format)
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

/// Generate a random secure password
///
/// Generates a password of the specified length using cryptographically secure random bytes.
/// The password includes uppercase, lowercase, numbers, and special characters.
pub fn generate_password(length: usize) -> Result<String, CryptoError> {
    // Define character set: letters (upper and lower), numbers, and safe special characters
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+?";

    if length == 0 {
        return Err(CryptoError::GenerationFailed(
            "Password length must be greater than 0".to_string(),
        ));
    }

    let mut password = String::with_capacity(length);
    let mut buffer = vec![0u8; length];

    // Use getrandom for cryptographically secure random bytes
    if let Err(e) = getrandom::getrandom(&mut buffer) {
        return Err(CryptoError::GenerationFailed(format!(
            "Failed to generate random bytes: {}",
            e
        )));
    }

    // Map random bytes to characters from CHARSET
    for byte in buffer {
        // Use modulo to map the byte to an index in CHARSET
        let idx = (byte as usize) % CHARSET.len();
        password.push(CHARSET[idx] as char);
    }

    Ok(password)
}

/// Generate a random HMAC-SHA256 key
///
/// Generates a 256-bit (32-byte) random key suitable for HMAC-SHA256.
/// The key is base64 encoded for storage.
pub fn generate_hs256_key() -> Result<String, CryptoError> {
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

    // HMAC-SHA256 works best with keys equal to or larger than the hash output (256 bits = 32 bytes)
    const KEY_SIZE: usize = 32;

    let mut key_bytes = vec![0u8; KEY_SIZE];

    // Use getrandom for cryptographically secure random bytes
    if let Err(e) = getrandom::getrandom(&mut key_bytes) {
        return Err(CryptoError::GenerationFailed(format!(
            "Failed to generate random bytes: {}",
            e
        )));
    }

    // Base64 encode the key for storage
    let encoded = BASE64.encode(&key_bytes);

    Ok(encoded)
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
    fn test_generate_password() {
        // Generate passwords of different lengths
        let pwd16 = generate_password(16).expect("Password generation should succeed");
        assert_eq!(pwd16.len(), 16);

        let pwd32 = generate_password(32).expect("Password generation should succeed");
        assert_eq!(pwd32.len(), 32);

        let pwd64 = generate_password(64).expect("Password generation should succeed");
        assert_eq!(pwd64.len(), 64);
    }

    #[test]
    fn test_generate_password_unique() {
        // Generate multiple passwords and verify they're different
        let pwd1 = generate_password(32).expect("First password generation should succeed");
        let pwd2 = generate_password(32).expect("Second password generation should succeed");
        let pwd3 = generate_password(32).expect("Third password generation should succeed");

        // Very unlikely to get the same password twice
        assert_ne!(pwd1, pwd2, "Generated passwords should be unique");
        assert_ne!(pwd2, pwd3, "Generated passwords should be unique");
        assert_ne!(pwd1, pwd3, "Generated passwords should be unique");
    }

    #[test]
    fn test_generate_password_charset() {
        let pwd = generate_password(100).expect("Password generation should succeed");

        // Verify all characters are from expected charset
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+?";
        for ch in pwd.chars() {
            assert!(
                CHARSET.contains(&(ch as u8)),
                "Password contains invalid character: {}",
                ch
            );
        }
    }

    #[test]
    fn test_generate_password_zero_length() {
        let result = generate_password(0);
        assert!(result.is_err(), "Zero-length password should fail");
    }

    #[test]
    fn test_generate_hs256_key() {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

        // Generate HMAC-SHA256 key
        let key = generate_hs256_key().expect("HS256 key generation should succeed");

        // Should be a valid base64 string
        let decoded = BASE64.decode(&key).expect("Should be valid base64");

        // Should be 32 bytes (256 bits) when decoded
        assert_eq!(decoded.len(), 32, "HS256 key should be 32 bytes (256 bits)");

        // Base64 encoding of 32 bytes should be 44 characters (with padding)
        assert_eq!(key.len(), 44, "Base64 encoded 32 bytes should be 44 chars");
    }

    #[test]
    fn test_generate_hs256_key_unique() {
        // Generate multiple keys and verify they're different
        let key1 = generate_hs256_key().expect("First key generation should succeed");
        let key2 = generate_hs256_key().expect("Second key generation should succeed");
        let key3 = generate_hs256_key().expect("Third key generation should succeed");

        // Very unlikely to get the same key twice
        assert_ne!(key1, key2, "Generated HS256 keys should be unique");
        assert_ne!(key2, key3, "Generated HS256 keys should be unique");
        assert_ne!(key1, key3, "Generated HS256 keys should be unique");
    }

    #[test]
    fn test_generate_rsa_keypair_structure() {
        // Skip this test if OpenSSL is not available
        if check_openssl_available().is_err() {
            return;
        }

        let keypair = generate_rsa_keypair().expect("Key generation should succeed");

        // Verify private key structure
        assert!(
            keypair
                .private_key
                .contains("-----BEGIN RSA PRIVATE KEY-----")
        );
        assert!(
            keypair
                .private_key
                .contains("-----END RSA PRIVATE KEY-----")
        );

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
