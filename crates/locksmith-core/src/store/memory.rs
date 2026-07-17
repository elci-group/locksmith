//! In-memory store: no persistence, used for tests and ephemeral daemons.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::audit::AuditRecord;
use crate::error::Result;
use crate::types::{Lease, QueueEntry, QueueEntryId};

use super::{Snapshot, Store};

#[derive(Default)]
pub struct InMemoryStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    leases: HashMap<(String, String), Lease>,
    queue: HashMap<QueueEntryId, QueueEntry>,
    audit: Vec<AuditRecord>,
    counters: HashMap<String, u64>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for InMemoryStore {
    fn put_lease(&self, lease: &Lease) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .leases
            .insert((lease.resource.clone(), lease.owner.clone()), lease.clone());
        Ok(())
    }

    fn remove_lease(&self, resource: &str, owner: &str) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .leases
            .remove(&(resource.to_string(), owner.to_string()));
        Ok(())
    }

    fn put_queue_entry(&self, entry: &QueueEntry) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .queue
            .insert(entry.id, entry.clone());
        Ok(())
    }

    fn remove_queue_entry(&self, id: QueueEntryId) -> Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queue
            .remove(&id);
        Ok(())
    }

    fn put_resource(&self, _id: &str, _kind: &str, _metadata: &serde_json::Value) -> Result<()> {
        Ok(())
    }

    fn put_owner(&self, _name: &str, _metadata: &serde_json::Value) -> Result<()> {
        Ok(())
    }

    fn append_audit(&self, record: &AuditRecord) -> Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .audit
            .push(record.clone());
        Ok(())
    }

    fn set_counter(&self, key: &str, value: u64) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .counters
            .insert(key.to_string(), value);
        Ok(())
    }

    fn load_snapshot(&self) -> Result<Snapshot> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let get = |k: &str| inner.counters.get(k).copied().unwrap_or(1);
        Ok(Snapshot {
            leases: inner.leases.values().cloned().collect(),
            queue: inner.queue.values().cloned().collect(),
            epochs: inner
                .counters
                .iter()
                .filter_map(|(k, v)| k.strip_prefix("epoch:").map(|r| (r.to_string(), *v)))
                .collect(),
            next_lease_id: get("lease_id"),
            next_queue_id: get("queue_id"),
            next_seq: get("seq"),
        })
    }

    fn audit_tail(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let skip = inner.audit.len().saturating_sub(limit);
        Ok(inner.audit.iter().skip(skip).cloned().collect())
    }

    fn audit_older_than(&self, cutoff_ms: u64) -> Result<Vec<AuditRecord>> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Ok(inner
            .audit
            .iter()
            .filter(|r| r.ts < cutoff_ms)
            .cloned()
            .collect())
    }

    fn prune_audit_older_than(&self, cutoff_ms: u64) -> Result<u64> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = inner.audit.len() as u64;
        inner.audit.retain(|r| r.ts >= cutoff_ms);
        let after = inner.audit.len() as u64;
        Ok(before - after)
    }
}
