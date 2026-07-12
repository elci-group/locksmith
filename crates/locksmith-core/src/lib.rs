//! # locksmith-core
//!
//! Deterministic workspace locking and coordination engine.
//!
//! * Every mutation happens under an explicit, bounded **lease**.
//! * Any addressable entity is lockable — a resource is just a string.
//! * Conflicting acquires enter a **queue** with a configurable policy.
//! * Missed heartbeats or elapsed lease times expire leases automatically;
//!   the next queued owner is promoted.
//! * Every transition is persisted to SQLite, appended to an immutable
//!   **audit log**, and published on the **event bus**.

pub mod audit;
pub mod error;
pub mod event;
pub mod hierarchy;
pub mod manager;
pub mod scheduler;
pub mod store;
pub mod types;

pub use audit::AuditRecord;
pub use error::{Error, Result};
pub use event::{Event, EventBus, EventKind};
pub use manager::{
    AcquireOutcome, AcquireRequest, LockManager, MetricsSnapshot, ResourceView, SweepReport,
};
pub use scheduler::QueuePolicy;
pub use store::{InMemoryStore, Snapshot, SqliteStore, Store};
pub use types::{
    now_ms, Config, Lease, LeaseCapability, LeaseId, LockMode, OwnerId, Priority, QueueEntry,
    QueueEntryId, ResourceId, TimestampMs,
};
