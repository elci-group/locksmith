//! Core types shared across Locksmith: resources, leases, queues, config.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

fn instant_now() -> Instant {
    Instant::now()
}

/// A bounded claim on a resource. Every lease expires — always.
///
/// Expiry and heartbeat timeouts are evaluated against monotonic `Instant`s
/// (immune to wall-clock steps); the wall-clock fields exist for
/// persistence, recovery and display. `reanchor` rebuilds the monotonic
/// anchors after a store replay.
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
    /// Fencing token: bumped on every grant and every ownership/mode change.
    pub epoch: u64,
    #[serde(skip, default = "instant_now")]
    pub deadline: Instant,
    #[serde(skip, default = "instant_now")]
    pub last_beat: Instant,
    #[serde(default)]
    pub capabilities: Vec<LeaseCapability>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl Lease {
    /// Recompute the monotonic anchors from the persisted wall-clock fields.
    /// Must be called once on every lease replayed from the store: `Instant`
    /// values are process-local and cannot be persisted.
    pub fn reanchor(&mut self, now_wall: TimestampMs) {
        let now = Instant::now();
        self.deadline = now + Duration::from_millis(self.expires_at.saturating_sub(now_wall));
        let beat_age = now_wall.saturating_sub(self.last_heartbeat);
        self.last_beat = now
            .checked_sub(Duration::from_millis(beat_age))
            .unwrap_or(now);
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    pub fn heartbeat_missed(&self) -> bool {
        self.last_beat.elapsed() >= Duration::from_millis(self.heartbeat_timeout_ms)
    }

    pub fn remaining_ms(&self) -> u64 {
        self.deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as u64
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
    /// Audit retention in days (default 30). Records older than this are
    /// exported (when `audit_archive_path` is set) and pruned, at most once
    /// per hour during the expiry sweep. 0 disables pruning.
    pub audit_retention_days: u64,
    /// JSONL file that receives exported audit records before pruning.
    pub audit_archive_path: Option<std::path::PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            default_lease_ms: 20 * 60 * 1000,
            default_heartbeat_interval_ms: 30 * 1000,
            default_heartbeat_timeout_ms: 90 * 1000,
            queue_policy: QueuePolicy::default(),
            event_buffer: 10_000,
            audit_retention_days: 30,
            audit_archive_path: None,
        }
    }
}
