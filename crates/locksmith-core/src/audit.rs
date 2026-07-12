//! Immutable audit log records.

use serde::{Deserialize, Serialize};

use crate::types::TimestampMs;

/// One entry in the append-only audit log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: TimestampMs,
    pub owner: String,
    pub action: String,
    pub resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl AuditRecord {
    pub fn new(
        owner: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        AuditRecord {
            ts: crate::types::now_ms(),
            owner: owner.into(),
            action: action.into(),
            resource: resource.into(),
            duration_ms: None,
            metadata: serde_json::json!({}),
        }
    }

    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
}
