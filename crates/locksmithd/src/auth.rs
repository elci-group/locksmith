//! Authentication and authorization for the Locksmith daemon.
//!
//! Two modes:
//! * **Anonymous** (default for local development): every caller gets the
//!   standard capability set, no identity required.
//! * **API keys**: a JSON file maps bearer tokens to owners and
//!   capabilities. `--no-anonymous` rejects unauthenticated requests.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Json;
use serde::{Deserialize, Serialize};

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
    pub fn load(path: Option<&std::path::Path>, allow_anonymous: bool) -> Result<Self, String> {
        match path {
            None => Ok(AuthConfig {
                keys: Vec::new(),
                allow_anonymous,
            }),
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .map_err(|e| format!("cannot read api keys file {}: {e}", p.display()))?;
                let file: AuthConfigFile = serde_json::from_str(&text)
                    .map_err(|e| format!("invalid api keys file {}: {e}", p.display()))?;
                Ok(AuthConfig {
                    keys: file.keys,
                    allow_anonymous,
                })
            }
        }
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
