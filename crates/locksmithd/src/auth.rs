//! Authentication and authorization for the Locksmith daemon.
//!
//! Two modes:
//! * **Anonymous** (default for local development): every caller gets the
//!   standard capability set, no identity required.
//! * **API keys**: a JSON file maps bearer tokens to owners and
//!   capabilities. `--no-anonymous` rejects unauthenticated requests.
//!
//! The API key file can be stored either as plaintext JSON (`--api-keys`)
//! or sealed at rest (`--api-keys-sealed`, see `locksmith trust seal-keys`).
//! A sealed file is unsealed once at startup using a `TrustProvider` keyed
//! by `--trust-key`; the decrypted keys never touch disk. See
//! `locksmith_core::trust` for what "sealed" does and doesn't protect
//! against with today's software-only backend.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Json;
use serde::{Deserialize, Serialize};

use locksmith_core::SoftwareProvider;

use crate::AppState;

/// Authorization capabilities from the technical directive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    Acquire,
    Release,
    Inspect,
    Transfer,
    Steal,
    Admin,
    Read,
    Write,
}

impl Capability {
    pub const STANDARD: &'static [Capability] = &[
        Capability::Acquire,
        Capability::Release,
        Capability::Inspect,
        Capability::Transfer,
        Capability::Read,
        Capability::Write,
    ];
}

/// One API key entry in the auth config file.
#[derive(Clone, Debug, Deserialize)]
pub struct ApiKey {
    pub key: String,
    pub owner: String,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

/// Daemon auth configuration file.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AuthConfigFile {
    #[serde(default)]
    pub keys: Vec<ApiKey>,
}

#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub keys: Vec<ApiKey>,
    pub allow_anonymous: bool,
}

impl AuthConfig {
    /// Load API keys from at most one of a plaintext (`path`) or sealed
    /// (`sealed_path`) file. `trust_key_path` locates the software trust
    /// provider's key, used only when `sealed_path` is set.
    pub fn load(
        path: Option<&std::path::Path>,
        sealed_path: Option<&std::path::Path>,
        trust_key_path: &std::path::Path,
        allow_anonymous: bool,
    ) -> Result<Self, String> {
        if path.is_some() && sealed_path.is_some() {
            return Err("--api-keys and --api-keys-sealed are mutually exclusive".into());
        }
        let keys = if let Some(p) = sealed_path {
            let provider = SoftwareProvider::open_or_create(trust_key_path)
                .map_err(|e| format!("cannot open trust key {}: {e}", trust_key_path.display()))?;
            let bytes = locksmith_core::unseal_from_file(&provider, p)
                .map_err(|e| format!("cannot unseal api keys file {}: {e}", p.display()))?;
            let file: AuthConfigFile = serde_json::from_slice(&bytes)
                .map_err(|e| format!("invalid sealed api keys file {}: {e}", p.display()))?;
            file.keys
        } else if let Some(p) = path {
            let text = std::fs::read_to_string(p)
                .map_err(|e| format!("cannot read api keys file {}: {e}", p.display()))?;
            let file: AuthConfigFile = serde_json::from_str(&text)
                .map_err(|e| format!("invalid api keys file {}: {e}", p.display()))?;
            file.keys
        } else {
            Vec::new()
        };
        Ok(AuthConfig {
            keys,
            allow_anonymous,
        })
    }

    fn authenticate(&self, headers: &HeaderMap) -> Option<(String, Vec<Capability>)> {
        let header = headers.get("authorization")?.to_str().ok()?;
        let token = header.strip_prefix("Bearer ")?;
        let key = self.keys.iter().find(|k| k.key == token)?;
        let caps = if key.capabilities.is_empty() {
            Capability::STANDARD.to_vec()
        } else {
            key.capabilities.clone()
        };
        Some((key.owner.clone(), caps))
    }
}

/// The authenticated (or anonymous) caller.
#[derive(Clone, Debug)]
pub struct Identity {
    pub owner: Option<String>,
    pub capabilities: Vec<Capability>,
}

impl Identity {
    pub fn has(&self, cap: Capability) -> bool {
        self.capabilities.contains(&Capability::Admin) || self.capabilities.contains(&cap)
    }

    pub fn require(&self, cap: Capability) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
        if self.has(cap) {
            Ok(())
        } else {
            Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": format!("missing capability '{}'", cap_name(cap))
                })),
            ))
        }
    }

    /// Resolve which owner an operation applies to: an authenticated identity
    /// pins the owner unless the caller is admin.
    pub fn resolve_owner(
        &self,
        requested: Option<&str>,
    ) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
        match (&self.owner, requested) {
            (Some(bound), Some(req)) if bound != req && !self.has(Capability::Admin) => Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": format!("identity is bound to owner '{bound}', cannot act as '{req}'")
                })),
            )),
            (Some(bound), _) => Ok(requested.unwrap_or(bound).to_string()),
            (None, Some(req)) => Ok(req.to_string()),
            (None, None) => Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "owner is required" })),
            )),
        }
    }
}

fn cap_name(cap: Capability) -> &'static str {
    match cap {
        Capability::Acquire => "acquire",
        Capability::Release => "release",
        Capability::Inspect => "inspect",
        Capability::Transfer => "transfer",
        Capability::Steal => "steal",
        Capability::Admin => "admin",
        Capability::Read => "read",
        Capability::Write => "write",
    }
}

impl FromRequestParts<AppState> for Identity {
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some((owner, capabilities)) = state.auth.authenticate(&parts.headers) {
            return Ok(Identity {
                owner: Some(owner),
                capabilities,
            });
        }
        if parts.headers.contains_key("authorization") {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "invalid api key" })),
            ));
        }
        if state.auth.allow_anonymous {
            return Ok(Identity {
                owner: None,
                capabilities: Capability::STANDARD.to_vec(),
            });
        }
        Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "authentication required" })),
        ))
    }
}
