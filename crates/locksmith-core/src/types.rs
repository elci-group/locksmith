//! Core types shared across Locksmith: resources, leases, queues, config.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::scheduler::QueuePolicy;

/// Wall-clock timestamp in milliseconds since the Unix epoch.
pub type TimestampMs = u64;

/// Current wall-clock time in milliseconds.
pub fn now_ms() -> TimestampMs {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Identifier of a lockable resource. Any addressable entity — files,
/// directories, GPUs, tasks, agents, deployment targets — is just a string.
///
/// Resources containing `/` participate in hierarchical locking:
/// `workspace/frontend/button.rs` has ancestors `workspace` and
/// `workspace/frontend`.
pub type ResourceId = String;

/// Identifier of a lease owner: a human, an agent, a CI job...
pub type OwnerId = String;

/// Unique lease identifier.
pub type LeaseId = u64;

/// Unique queue entry identifier.
pub type QueueEntryId = u64;

/// Lock mode requested or held on a resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockMode {
    /// Unlimited readers, no writers.
    Shared,
    /// Single owner, blocks every other mode.
    Exclusive,
    /// Reserve an upcoming write (database-style intent lock).
    Intent,
}

impl LockMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            LockMode::Shared => "shared",
            LockMode::Exclusive => "exclusive",
            LockMode::Intent => "intent",
        }
    }

    pub fn parse(s: &str) -> Option<LockMode> {
        match s {
            "shared" | "s" | "read" => Some(LockMode::Shared),
            "exclusive" | "x" | "write" => Some(LockMode::Exclusive),
            "intent" | "i" => Some(LockMode::Intent),
            _ => None,
        }
    }
}

/// Queue priority. Higher priority waiters are promoted first under the
/// `priority` and `weighted_fair` queue policies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    Low = 0,
    #[default]
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl Priority {
    pub fn parse(s: &str) -> Option<Priority> {
        match s {
            "low" => Some(Priority::Low),
            "normal" => Some(Priority::Normal),
            "high" => Some(Priority::High),
            "critical" => Some(Priority::Critical),
            _ => None,
        }
    }
}

/// What the holder of a lease may do with the resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeaseCapability {
    Read,
    Write,
}

/// A bounded claim on a resource. Every lease expires — always.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lease {
    pub id: LeaseId,
    pub resource: ResourceId,
    pub owner: OwnerId,
    pub mode: LockMode,
    pub priority: Priority,
    pub acquired_at: TimestampMs,
    pub expires_at: TimestampMs,
    pub lease_duration_ms: u64,
    pub last_heartbeat: TimestampMs,
    pub heartbeat_interval_ms: u64,
    pub heartbeat_timeout_ms: u64,
    #[serde(default)]
    pub capabilities: Vec<LeaseCapability>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl Lease {
    pub fn is_expired(&self, now: TimestampMs) -> bool {
        now >= self.expires_at
    }

    pub fn heartbeat_missed(&self, now: TimestampMs) -> bool {
        now >= self.last_heartbeat + self.heartbeat_timeout_ms
    }

    pub fn remaining_ms(&self, now: TimestampMs) -> u64 {
        self.expires_at.saturating_sub(now)
    }
}

/// A waiter in a resource queue.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueueEntry {
    pub id: QueueEntryId,
    /// Global monotonic sequence number (FIFO ordering).
    pub seq: u64,
    pub resource: ResourceId,
    pub owner: OwnerId,
    pub mode: LockMode,
    pub priority: Priority,
    pub requested_at: TimestampMs,
    pub lease_duration_ms: u64,
    pub heartbeat_interval_ms: u64,
    pub heartbeat_timeout_ms: u64,
    #[serde(default)]
    pub capabilities: Vec<LeaseCapability>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Daemon / manager configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Default lease duration: 20 minutes.
    pub default_lease_ms: u64,
    /// Default heartbeat interval: 30 seconds.
    pub default_heartbeat_interval_ms: u64,
    /// Default heartbeat timeout: 90 seconds (three missed beats).
    pub default_heartbeat_timeout_ms: u64,
    /// Queue scheduling policy.
    pub queue_policy: QueuePolicy,
    /// How many events the in-memory event ring buffer retains.
    pub event_buffer: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            default_lease_ms: 20 * 60 * 1000,
            default_heartbeat_interval_ms: 30 * 1000,
            default_heartbeat_timeout_ms: 90 * 1000,
            queue_policy: QueuePolicy::default(),
            event_buffer: 10_000,
        }
    }
}
