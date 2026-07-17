//! Persistence layer.
//!
//! The lock manager keeps authoritative state in memory and writes every
//! mutation through a `Store`. On startup the store is replayed into memory
//! (`load_snapshot`), stale leases are expired, and queues resume — that is
//! the crash recovery path.

pub mod memory;
pub mod sqlite;

pub use memory::InMemoryStore;
pub use sqlite::SqliteStore;

use crate::audit::AuditRecord;
use crate::error::Result;
use crate::types::{Lease, QueueEntry, QueueEntryId};

/// Full persistent state, replayed into memory at startup.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub leases: Vec<Lease>,
    pub queue: Vec<QueueEntry>,
    /// Per-resource fencing epochs (persisted as `epoch:<resource>` counters).
    pub epochs: Vec<(crate::types::ResourceId, u64)>,
    pub next_lease_id: u64,
    pub next_queue_id: u64,
    pub next_seq: u64,
}

/// Write-through persistence for the lock manager.
pub trait Store: Send + Sync {
    /// Insert or replace a lease.
    fn put_lease(&self, lease: &Lease) -> Result<()>;
    /// Remove the lease held by `owner` on `resource`, if any.
    fn remove_lease(&self, resource: &str, owner: &str) -> Result<()>;
    /// Insert or replace a queue entry.
    fn put_queue_entry(&self, entry: &QueueEntry) -> Result<()>;
    /// Remove a queue entry by id.
    fn remove_queue_entry(&self, id: QueueEntryId) -> Result<()>;
    /// Register (or update) a resource in the registry.
    fn put_resource(&self, id: &str, kind: &str, metadata: &serde_json::Value) -> Result<()>;
    /// Register (or update) an owner.
    fn put_owner(&self, name: &str, metadata: &serde_json::Value) -> Result<()>;
    /// Append to the immutable audit log.
    fn append_audit(&self, record: &AuditRecord) -> Result<()>;
    /// Persist a monotonic counter (lease id, queue id, event seq).
    fn set_counter(&self, key: &str, value: u64) -> Result<()>;
    /// Replay the full persistent state.
    fn load_snapshot(&self) -> Result<Snapshot>;
    /// Most recent audit records, oldest first.
    fn audit_tail(&self, limit: usize) -> Result<Vec<AuditRecord>>;
    /// Audit records older than `cutoff_ms`, oldest first (read for archival
    /// export before pruning).
    fn audit_older_than(&self, cutoff_ms: u64) -> Result<Vec<AuditRecord>>;
    /// Prune audit records older than `cutoff_ms` (wall-clock timestamp).
    fn prune_audit_older_than(&self, cutoff_ms: u64) -> Result<u64>;
}
