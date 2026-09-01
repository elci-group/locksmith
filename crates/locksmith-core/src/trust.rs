//! Sealing secrets at rest, behind a swappable trust backend.
//!
//! `TrustProvider` abstracts over what actually holds the sealing key.
//! Today there is one real implementation, [`SoftwareProvider`]: a
//! locally-persisted AES-256-GCM key. [`tpm2_present`] only detects whether
//! a TPM2 character device exists on this machine — there is no TPM2
//! backend yet, so detection does not change sealing behavior. Keeping the
//! trait in place now means a future `Tpm2Provider` (sealing this same key
//! material to the TPM, optionally bound to PCR state) is a new
//! implementation of `TrustProvider`, not a rework of every caller.
//!
//! Do not read hardware-backed guarantees into `SoftwareProvider`:
//! possession of its key file is sufficient to unseal, exactly like any
//! other software secret. It exists so callers have one sealing interface
//! regardless of which backend is available.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AesGcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Which backend produced a [`SealedBlob`]. Carried alongside the blob so a
/// provider can refuse to unseal data it didn't (or couldn't have) sealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityMode {
    /// AES-256-GCM with a key persisted on the local filesystem.
    Software,
    /// TPM2-sealed. Not implemented yet.
    Tpm2,
}

impl fmt::Display for SecurityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityMode::Software => write!(f, "software"),
            SecurityMode::Tpm2 => write!(f, "tpm2"),
        }
    }
}

/// What a `TrustProvider` can do, for status reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustCapabilities {
    pub security_mode: SecurityMode,
    /// True if unsealing requires more than filesystem access to this
    /// process's host (e.g. a hardware root of trust).
    pub hardware_backed: bool,
}

/// A sealed secret, serializable directly as the on-disk representation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedBlob {
    pub security_mode: SecurityMode,
    /// Base64-encoded nonce.
    pub nonce: String,
    /// Base64-encoded ciphertext (includes the AEAD tag).
    pub ciphertext: String,
}

#[derive(Debug)]
pub enum TrustError {
    Io(io::Error),
    Crypto(String),
    UnsupportedMode(SecurityMode),
    Format(String),
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustError::Io(e) => write!(f, "{e}"),
            TrustError::Crypto(msg) => write!(f, "crypto error: {msg}"),
            TrustError::UnsupportedMode(mode) => {
                write!(f, "this provider cannot unseal '{mode}' blobs")
            }
            TrustError::Format(msg) => write!(f, "malformed sealed data: {msg}"),
        }
    }
}

impl std::error::Error for TrustError {}

impl From<io::Error> for TrustError {
    fn from(e: io::Error) -> Self {
        TrustError::Io(e)
    }
}

/// Detect a TPM2 character device (`/dev/tpmrm0`, falling back to the raw
/// `/dev/tpm0`). Detection only — no TPM2 `TrustProvider` exists yet, so
/// this does not change which backend `seal`/`unseal` use.
pub fn tpm2_present() -> bool {
    Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
}

/// Seals and unseals bytes. Implementations own the key material; callers
/// never see it.
pub trait TrustProvider: Send + Sync {
    fn capabilities(&self) -> TrustCapabilities;
    fn seal(&self, plaintext: &[u8]) -> Result<SealedBlob, TrustError>;
    fn unseal(&self, sealed: &SealedBlob) -> Result<Vec<u8>, TrustError>;
}

/// AES-256-GCM sealing with a key persisted at a fixed path, generated on
/// first use. This is the `SOFTWARE_ONLY` trust backend (see module docs):
/// it protects against casual disclosure (e.g. a stray file copy that
/// misses the key), not against a full compromise of this host.
pub struct SoftwareProvider {
    key: Key<Aes256Gcm>,
}

impl SoftwareProvider {
    /// Load the 32-byte key at `key_path`, or generate and persist
    /// (mode 0600 on unix) a new random one if it doesn't exist yet.
    pub fn open_or_create(key_path: &Path) -> Result<Self, TrustError> {
        let key_bytes: Vec<u8> = if key_path.exists() {
            let raw = fs::read(key_path)?;
            if raw.len() != 32 {
                return Err(TrustError::Format(format!(
                    "trust key at {} is {} bytes, expected 32",
                    key_path.display(),
                    raw.len()
                )));
            }
            raw
        } else {
            if let Some(parent) = key_path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            let mut key = [0u8; 32];
            aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut OsRng, &mut key);
            write_private(key_path, &key)?;
            key.to_vec()
        };
        Ok(SoftwareProvider {
            key: *Key::<Aes256Gcm>::from_slice(&key_bytes),
        })
    }

    fn cipher(&self) -> AesGcm<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U12> {
        Aes256Gcm::new(&self.key)
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), TrustError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), TrustError> {
    fs::write(path, bytes)?;
    Ok(())
}

impl TrustProvider for SoftwareProvider {
    fn capabilities(&self) -> TrustCapabilities {
        TrustCapabilities {
            security_mode: SecurityMode::Software,
            hardware_backed: false,
        }
    }

    fn seal(&self, plaintext: &[u8]) -> Result<SealedBlob, TrustError> {
        use aes_gcm::AeadCore;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher()
            .encrypt(&nonce, plaintext)
            .map_err(|e| TrustError::Crypto(e.to_string()))?;
        Ok(SealedBlob {
            security_mode: SecurityMode::Software,
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        })
    }

    fn unseal(&self, sealed: &SealedBlob) -> Result<Vec<u8>, TrustError> {
        if sealed.security_mode != SecurityMode::Software {
            return Err(TrustError::UnsupportedMode(sealed.security_mode));
        }
        let nonce_bytes = BASE64
            .decode(&sealed.nonce)
            .map_err(|e| TrustError::Format(e.to_string()))?;
        let ciphertext = BASE64
            .decode(&sealed.ciphertext)
            .map_err(|e| TrustError::Format(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.cipher()
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| TrustError::Crypto(e.to_string()))
    }
}

/// On-disk envelope wrapping a [`SealedBlob`], versioned so the format can
/// evolve without breaking existing sealed files.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedFile {
    pub version: u32,
    pub sealed: SealedBlob,
}

/// Seal `plaintext` and write it as a `SealedFile` envelope to `out_path`.
pub fn seal_to_file(
    provider: &dyn TrustProvider,
    plaintext: &[u8],
    out_path: &Path,
) -> Result<(), TrustError> {
    let sealed = provider.seal(plaintext)?;
    let envelope = SealedFile { version: 1, sealed };
    let json =
        serde_json::to_vec_pretty(&envelope).map_err(|e| TrustError::Format(e.to_string()))?;
    write_private(out_path, &json)?;
    Ok(())
}

/// Read a `SealedFile` envelope from `in_path` and unseal it.
pub fn unseal_from_file(
    provider: &dyn TrustProvider,
    in_path: &Path,
) -> Result<Vec<u8>, TrustError> {
    let raw = fs::read(in_path)?;
    let envelope: SealedFile =
        serde_json::from_slice(&raw).map_err(|e| TrustError::Format(e.to_string()))?;
    provider.unseal(&envelope.sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "locksmith-trust-test-{}-{}-{name}",
            std::process::id(),
            crate::types::now_ms(),
        ))
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let key_path = temp_path("key");
        let provider = SoftwareProvider::open_or_create(&key_path).unwrap();
        let sealed = provider.seal(b"top secret").unwrap();
        assert_eq!(sealed.security_mode, SecurityMode::Software);
        let plaintext = provider.unseal(&sealed).unwrap();
        assert_eq!(plaintext, b"top secret");
        let _ = fs::remove_file(&key_path);
    }

    #[test]
    fn key_persists_across_providers() {
        let key_path = temp_path("key-persist");
        let sealed = {
            let provider = SoftwareProvider::open_or_create(&key_path).unwrap();
            provider.seal(b"payload").unwrap()
        };
        // A second provider loading the same key file must decrypt it.
        let provider2 = SoftwareProvider::open_or_create(&key_path).unwrap();
        assert_eq!(provider2.unseal(&sealed).unwrap(), b"payload");
        let _ = fs::remove_file(&key_path);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key_path = temp_path("key-tamper");
        let provider = SoftwareProvider::open_or_create(&key_path).unwrap();
        let mut sealed = provider.seal(b"payload").unwrap();
        // Flip a byte in the ciphertext: GCM must reject it rather than
        // silently returning corrupted plaintext.
        let mut bytes = BASE64.decode(&sealed.ciphertext).unwrap();
        bytes[0] ^= 0xff;
        sealed.ciphertext = BASE64.encode(bytes);
        assert!(provider.unseal(&sealed).is_err());
        let _ = fs::remove_file(&key_path);
    }

    #[test]
    fn file_roundtrip() {
        let key_path = temp_path("key-file");
        let out_path = temp_path("sealed.json");
        let provider = SoftwareProvider::open_or_create(&key_path).unwrap();
        seal_to_file(&provider, br#"{"keys":[]}"#, &out_path).unwrap();
        let plaintext = unseal_from_file(&provider, &out_path).unwrap();
        assert_eq!(plaintext, br#"{"keys":[]}"#);
        let _ = fs::remove_file(&key_path);
        let _ = fs::remove_file(&out_path);
    }

    #[test]
    fn wrong_key_cannot_unseal() {
        let key_path_a = temp_path("key-a");
        let key_path_b = temp_path("key-b");
        let provider_a = SoftwareProvider::open_or_create(&key_path_a).unwrap();
        let provider_b = SoftwareProvider::open_or_create(&key_path_b).unwrap();
        let sealed = provider_a.seal(b"payload").unwrap();
        assert!(provider_b.unseal(&sealed).is_err());
        let _ = fs::remove_file(&key_path_a);
        let _ = fs::remove_file(&key_path_b);
    }
}
