//! The lease manager: deterministic ownership, queue scheduling, heartbeat
//! expiry and crash recovery.
//!
//! All state transitions are:
//! * applied to the in-memory state,
//! * written through to the `Store`,
//! * appended to the audit log,
//! * published on the event bus.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::audit::AuditRecord;
use crate::error::{Error, Result};
use crate::event::{Event, EventBus, EventKind};
use crate::hierarchy;
use crate::scheduler::QueuePolicy;
use crate::store::{Snapshot, Store};
use crate::types::{
    now_ms, Config, Lease, LeaseCapability, LeaseId, LockMode, OwnerId, Priority, QueueEntry,
    QueueEntryId, ResourceId, TimestampMs,
};

/// Strength ordering for promotion logic: Exclusive > Intent > Shared.
fn strength(mode: LockMode) -> u8 {
    match mode {
        LockMode::Shared => 0,
        LockMode::Intent => 1,
        LockMode::Exclusive => 2,
    }
}

/// Same-resource compatibility matrix.
fn modes_compatible(held: LockMode, requested: LockMode) -> bool {
    match (held, requested) {
        (LockMode::Exclusive, _) | (_, LockMode::Exclusive) => false,
        _ => true, // shared/shared, shared/intent, intent/intent
    }
}

/// Does a lock held on an ancestor block `requested` on a descendant?
fn ancestor_blocks(held: LockMode, requested: LockMode) -> bool {
    match held {
        LockMode::Exclusive => true,
        LockMode::Intent => requested == LockMode::Exclusive,
        LockMode::Shared => matches!(requested, LockMode::Exclusive | LockMode::Intent),
    }
}

/// Does a lock held on a descendant block `requested` on the ancestor?
fn descendant_blocks(requested: LockMode, held: LockMode) -> bool {
    match requested {
        LockMode::Exclusive => true,
        LockMode::Shared => matches!(held, LockMode::Exclusive | LockMode::Intent),
        LockMode::Intent => held == LockMode::Exclusive,
    }
}

/// Infer a resource kind from its id prefix (`gpu:0` -> `gpu`).
fn infer_kind(id: &str) -> &str {
    match id.find(':') {
        Some(i) if !id[..i].contains('/') => &id[..i],
        _ => "resource",
    }
}

/// Request to acquire a lease.
#[derive(Clone, Debug)]
pub struct AcquireRequest {
    pub resource: ResourceId,
    pub owner: OwnerId,
    pub mode: LockMode,
    pub priority: Priority,
    pub lease_duration_ms: Option<u64>,
    pub heartbeat_interval_ms: Option<u64>,
    pub heartbeat_timeout_ms: Option<u64>,
    pub capabilities: Vec<LeaseCapability>,
    pub metadata: serde_json::Value,
}

impl AcquireRequest {
    pub fn new(resource: impl Into<ResourceId>, owner: impl Into<OwnerId>, mode: LockMode) -> Self {
        AcquireRequest {
            resource: resource.into(),
            owner: owner.into(),
            mode,
            priority: Priority::default(),
            lease_duration_ms: None,
            heartbeat_interval_ms: None,
            heartbeat_timeout_ms: None,
            capabilities: Vec::new(),
            metadata: serde_json::json!({}),
        }
    }

    pub fn priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    pub fn lease_ms(mut self, ms: u64) -> Self {
        self.lease_duration_ms = Some(ms);
        self
    }

    pub fn metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Result of an acquire attempt.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum AcquireOutcome {
    /// Lease granted immediately.
    Granted { lease: Lease },
    /// Owner already holds a sufficient lease (recursive ownership).
    Held { lease: Lease },
    /// Queued behind conflicting holders.
    Queued { entry: QueueEntry, position: usize },
}

/// What `inspect` returns for a resource.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceView {
    pub resource: ResourceId,
    pub leases: Vec<Lease>,
    pub queue: Vec<QueueEntry>,
    pub ancestor_locks: Vec<Lease>,
    pub descendant_locks: Vec<Lease>,
}

/// Outcome of an expiry sweep.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SweepReport {
    pub expired: Vec<Lease>,
    pub promoted: Vec<Lease>,
}

/// Atomic operation counters.
#[derive(Default)]
struct Metrics {
    acquires: AtomicU64,
    grants: AtomicU64,
    queued: AtomicU64,
    releases: AtomicU64,
    renewals: AtomicU64,
    heartbeats: AtomicU64,
    expirations: AtomicU64,
    steals: AtomicU64,
    transfers: AtomicU64,
    promotions: AtomicU64,
    downgrades: AtomicU64,
    conflicts: AtomicU64,
    queue_promotions: AtomicU64,
}

/// Point-in-time metrics snapshot (counters + gauges).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub acquires: u64,
    pub grants: u64,
    pub queued: u64,
    pub releases: u64,
    pub renewals: u64,
    pub heartbeats: u64,
    pub expirations: u64,
    pub steals: u64,
    pub transfers: u64,
    pub promotions: u64,
    pub downgrades: u64,
    pub conflicts: u64,
    pub queue_promotions: u64,
    pub active_leases: u64,
    pub queue_depth: u64,
}

struct State {
    leases: HashMap<ResourceId, Vec<Lease>>,
    queue: HashMap<ResourceId, Vec<QueueEntry>>,
    next_lease_id: LeaseId,
    next_queue_id: QueueEntryId,
    next_seq: u64,
}

impl State {
    fn from_snapshot(snapshot: Snapshot) -> Self {
        let mut leases: HashMap<ResourceId, Vec<Lease>> = HashMap::new();
        for lease in snapshot.leases {
            leases
                .entry(lease.resource.clone())
                .or_default()
                .push(lease);
        }
        let mut queue: HashMap<ResourceId, Vec<QueueEntry>> = HashMap::new();
        for entry in snapshot.queue {
            queue.entry(entry.resource.clone()).or_default().push(entry);
        }
        State {
            leases,
            queue,
            next_lease_id: snapshot.next_lease_id.max(1),
            next_queue_id: snapshot.next_queue_id.max(1),
            next_seq: snapshot.next_seq.max(1),
        }
    }

    fn total_leases(&self) -> u64 {
        self.leases.values().map(|v| v.len() as u64).sum()
    }

    fn total_queued(&self) -> u64 {
        self.queue.values().map(|v| v.len() as u64).sum()
    }

    /// Find a conflicting lock for `owner` requesting `mode` on `resource`.
    /// Same-owner locks never conflict (recursive ownership).
    fn find_conflict(&self, resource: &str, owner: &str, mode: LockMode) -> Option<String> {
        // Same resource, other owners.
        if let Some(leases) = self.leases.get(resource) {
            for lease in leases {
                if lease.owner != owner && !modes_compatible(lease.mode, mode) {
                    return Some(format!(
                        "'{}' holds {} on '{}'",
                        lease.owner,
                        lease.mode.as_str(),
                        resource
                    ));
                }
            }
        }
        // Ancestors.
        for anc in hierarchy::ancestors(resource) {
            if let Some(leases) = self.leases.get(&anc) {
                for lease in leases {
                    if lease.owner != owner && ancestor_blocks(lease.mode, mode) {
                        return Some(format!(
                            "'{}' holds {} on ancestor '{}'",
                            lease.owner,
                            lease.mode.as_str(),
                            anc
                        ));
                    }
                }
            }
        }
        // Descendants.
        for (res, leases) in &self.leases {
            if !hierarchy::is_ancestor(resource, res) {
                continue;
            }
            for lease in leases {
                if lease.owner != owner && descendant_blocks(mode, lease.mode) {
                    return Some(format!(
                        "'{}' holds {} on descendant '{}'",
                        lease.owner,
                        lease.mode.as_str(),
                        res
                    ));
                }
            }
        }
        None
    }
}

/// The lease manager. Generic over the persistence store.
///
/// Mutex poisoning is recovered (`into_inner`) rather than propagated: a
/// panicked worker must not take the whole coordination service down. The
/// write-through store is the source of truth — a restart replays it — so
/// continuing under a potentially inconsistent in-memory state is safe
/// relative to the alternative (a dead daemon holding every lease).
pub struct LockManager<S: Store> {
    state: Mutex<State>,
    store: S,
    bus: Mutex<EventBus>,
    config: Config,
    metrics: Metrics,
}

impl<S: Store> LockManager<S> {
    /// Open the manager: replay the store, expire stale leases, resume queues.
    pub fn new(store: S, config: Config) -> Result<Self> {
        let snapshot = store.load_snapshot()?;
        let restored_leases = snapshot.leases.len();
        let restored_queue = snapshot.queue.len();
        let manager = LockManager {
            state: Mutex::new(State::from_snapshot(snapshot)),
            store,
            bus: Mutex::new(EventBus::new(config.event_buffer)),
            config,
            metrics: Metrics::default(),
        };
        let report = manager.sweep()?;
        manager.bus.lock().unwrap_or_else(|e| e.into_inner()).emit(
            EventKind::RecoveryCompleted,
            "",
            "locksmith",
            serde_json::json!({
                "restored_leases": restored_leases,
                "restored_queue": restored_queue,
                "expired_on_recovery": report.expired.len(),
            }),
        );
        Ok(manager)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    // ------------------------------------------------------------------
    // Acquire
    // ------------------------------------------------------------------

    pub fn acquire(&self, req: AcquireRequest) -> Result<AcquireOutcome> {
        self.metrics.acquires.fetch_add(1, Ordering::Relaxed);
        let resource = hierarchy::normalize(&req.resource);
        if resource.is_empty() {
            return Err(Error::Invalid("empty resource id".into()));
        }
        let now = now_ms();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Recursive ownership: owner already holds this resource.
        if let Some(existing) = state
            .leases
            .get(&resource)
            .and_then(|ls| ls.iter().find(|l| l.owner == req.owner))
            .cloned()
        {
            if strength(existing.mode) >= strength(req.mode) {
                return Ok(AcquireOutcome::Held { lease: existing });
            }
            // Stronger mode requested: in-place upgrade if uncontested.
            if state
                .find_conflict(&resource, &req.owner, req.mode)
                .is_none()
            {
                let lease = self.upgrade_mode(&mut state, &resource, &req.owner, req.mode)?;
                return Ok(AcquireOutcome::Granted { lease });
            }
            // Otherwise fall through to the queue with the stronger mode.
        }

        if state
            .find_conflict(&resource, &req.owner, req.mode)
            .is_none()
        {
            let lease = self.grant(&mut state, &req, &resource, now)?;
            return Ok(AcquireOutcome::Granted { lease });
        }

        // Conflict: enqueue (idempotent per owner).
        let conflict = state
            .find_conflict(&resource, &req.owner, req.mode)
            .unwrap_or_default();
        self.metrics.conflicts.fetch_add(1, Ordering::Relaxed);
        let entries = state.queue.entry(resource.clone()).or_default();
        if let Some(pos) = entries.iter().position(|e| e.owner == req.owner) {
            let entry = entries[pos].clone();
            let position = self.queue_position(&state, &resource, entry.id);
            return Ok(AcquireOutcome::Queued { entry, position });
        }

        let entry = QueueEntry {
            id: self.alloc_queue_id(&mut state)?,
            seq: self.alloc_seq(&mut state)?,
            resource: resource.clone(),
            owner: req.owner.clone(),
            mode: req.mode,
            priority: req.priority,
            requested_at: now,
            lease_duration_ms: req
                .lease_duration_ms
                .unwrap_or(self.config.default_lease_ms),
            heartbeat_interval_ms: req
                .heartbeat_interval_ms
                .unwrap_or(self.config.default_heartbeat_interval_ms),
            heartbeat_timeout_ms: req
                .heartbeat_timeout_ms
                .unwrap_or(self.config.default_heartbeat_timeout_ms),
            capabilities: req.capabilities.clone(),
            metadata: req.metadata.clone(),
        };
        self.store.put_queue_entry(&entry)?;
        state
            .queue
            .entry(resource.clone())
            .or_default()
            .push(entry.clone());
        let position = self.queue_position(&state, &resource, entry.id);
        self.metrics.queued.fetch_add(1, Ordering::Relaxed);

        self.store.append_audit(
            &AuditRecord::new(&req.owner, "queue", &resource)
                .with_metadata(serde_json::json!({ "mode": req.mode.as_str() })),
        )?;
        let mut bus = self.bus.lock().unwrap_or_else(|e| e.into_inner());
        bus.emit(
            EventKind::ConflictDetected,
            &resource,
            &req.owner,
            serde_json::json!({ "reason": conflict }),
        );
        bus.emit(
            EventKind::QueueEntered,
            &resource,
            &req.owner,
            serde_json::json!({ "position": position, "mode": req.mode.as_str() }),
        );
        Ok(AcquireOutcome::Queued { entry, position })
    }

    fn grant(
        &self,
        state: &mut State,
        req: &AcquireRequest,
        resource: &str,
        now: TimestampMs,
    ) -> Result<Lease> {
        let duration = req
            .lease_duration_ms
            .unwrap_or(self.config.default_lease_ms);
        let lease = Lease {
            id: self.alloc_lease_id(state)?,
            resource: resource.to_string(),
            owner: req.owner.clone(),
            mode: req.mode,
            priority: req.priority,
            acquired_at: now,
            expires_at: now + duration,
            lease_duration_ms: duration,
            last_heartbeat: now,
            heartbeat_interval_ms: req
                .heartbeat_interval_ms
                .unwrap_or(self.config.default_heartbeat_interval_ms),
            heartbeat_timeout_ms: req
                .heartbeat_timeout_ms
                .unwrap_or(self.config.default_heartbeat_timeout_ms),
            capabilities: req.capabilities.clone(),
            metadata: req.metadata.clone(),
        };
        self.store.put_lease(&lease)?;
        self.store.put_owner(&lease.owner, &serde_json::json!({}))?;
        self.store
            .put_resource(resource, infer_kind(resource), &serde_json::json!({}))?;
        state
            .leases
            .entry(resource.to_string())
            .or_default()
            .push(lease.clone());
        self.metrics.grants.fetch_add(1, Ordering::Relaxed);
        self.store.append_audit(
            &AuditRecord::new(&lease.owner, "acquire", resource).with_metadata(serde_json::json!({
                "mode": lease.mode.as_str(),
                "lease_ms": lease.lease_duration_ms,
            })),
        )?;
        self.bus.lock().unwrap_or_else(|e| e.into_inner()).emit(
            EventKind::LockAcquired,
            resource,
            &lease.owner,
            serde_json::json!({
                "mode": lease.mode.as_str(),
                "expires_at": lease.expires_at,
            }),
        );
        Ok(lease)
    }

    fn upgrade_mode(
        &self,
        state: &mut State,
        resource: &str,
        owner: &str,
        mode: LockMode,
    ) -> Result<Lease> {
        let leases = state
            .leases
            .get_mut(resource)
            .ok_or_else(|| Error::NotHeld {
                resource: resource.into(),
                owner: owner.into(),
            })?;
        let lease = leases
            .iter_mut()
            .find(|l| l.owner == owner)
            .ok_or_else(|| Error::NotHeld {
                resource: resource.into(),
                owner: owner.into(),
            })?;
        lease.mode = mode;
        let lease = lease.clone();
        self.store.put_lease(&lease)?;
        self.metrics.promotions.fetch_add(1, Ordering::Relaxed);
        self.store.append_audit(
            &AuditRecord::new(owner, "promote", resource)
                .with_metadata(serde_json::json!({ "mode": mode.as_str() })),
        )?;
        self.bus.lock().unwrap_or_else(|e| e.into_inner()).emit(
            EventKind::LockPromoted,
            resource,
            owner,
            serde_json::json!({ "mode": mode.as_str() }),
        );
        Ok(lease)
    }

    // ------------------------------------------------------------------
    // Release
    // ------------------------------------------------------------------

    pub fn release(&self, resource: &str, owner: &str) -> Result<Vec<Lease>> {
        let resource = hierarchy::normalize(resource);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let removed = self.remove_lease_inner(&mut state, &resource, owner, "release")?;
        match removed {
            None => Err(Error::NotHeld {
                resource,
                owner: owner.into(),
            }),
            Some(_) => {
                self.metrics.releases.fetch_add(1, Ordering::Relaxed);
                let promoted = self.promote_related(&mut state, &resource)?;
                Ok(promoted)
            }
        }
    }

    /// Remove a lease held by `owner` on `resource`, emitting events.
    /// Returns the removed lease.
    fn remove_lease_inner(
        &self,
        state: &mut State,
        resource: &str,
        owner: &str,
        action: &str,
    ) -> Result<Option<Lease>> {
        let Some(leases) = state.leases.get_mut(resource) else {
            return Ok(None);
        };
        let Some(pos) = leases.iter().position(|l| l.owner == owner) else {
            return Ok(None);
        };
        let lease = leases.remove(pos);
        if leases.is_empty() {
            state.leases.remove(resource);
        }
        self.store.remove_lease(resource, owner)?;
        let held_ms = now_ms().saturating_sub(lease.acquired_at);
        self.store
            .append_audit(&AuditRecord::new(owner, action, resource).with_duration(held_ms))?;
        self.bus.lock().unwrap_or_else(|e| e.into_inner()).emit(
            EventKind::LockReleased,
            resource,
            owner,
            serde_json::json!({ "action": action, "held_ms": held_ms }),
        );
        Ok(Some(lease))
    }

    // ------------------------------------------------------------------
    // Renew & heartbeat
    // ------------------------------------------------------------------

    pub fn renew(&self, resource: &str, owner: &str) -> Result<Lease> {
        let resource = hierarchy::normalize(resource);
        let now = now_ms();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let lease = self.mutate_lease(&mut state, &resource, owner, |lease| {
            lease.expires_at = now + lease.lease_duration_ms;
            lease.last_heartbeat = now;
        })?;
        self.metrics.renewals.fetch_add(1, Ordering::Relaxed);
        self.store.append_audit(
            &AuditRecord::new(owner, "renew", &resource)
                .with_metadata(serde_json::json!({ "expires_at": lease.expires_at })),
        )?;
        self.bus.lock().unwrap_or_else(|e| e.into_inner()).emit(
            EventKind::LockRenewed,
            &resource,
            owner,
            serde_json::json!({ "expires_at": lease.expires_at }),
        );
        Ok(lease)
    }

    /// Heartbeat one owner's leases — all of them, or a subset of resources.
    /// Returns the number of leases refreshed.
    pub fn heartbeat(&self, owner: &str, resources: Option<&[String]>) -> Result<usize> {
        let now = now_ms();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let filter: Option<Vec<String>> =
            resources.map(|rs| rs.iter().map(|r| hierarchy::normalize(r)).collect());
        let mut count = 0usize;
        for (resource, leases) in state.leases.iter_mut() {
            if let Some(f) = &filter {
                if !f.contains(resource) {
                    continue;
                }
            }
            for lease in leases.iter_mut() {
                if lease.owner != owner {
                    continue;
                }
                lease.last_heartbeat = now;
                let updated = lease.clone();
                self.store.put_lease(&updated)?;
                count += 1;
                self.bus.lock().unwrap_or_else(|e| e.into_inner()).emit(
                    EventKind::Heartbeat,
                    resource,
                    owner,
                    serde_json::json!({}),
                );
            }
        }
        if count > 0 {
            self.store.append_audit(
                &AuditRecord::new(owner, "heartbeat", "*")
                    .with_metadata(serde_json::json!({ "leases": count })),
            )?;
        }
        self.metrics
            .heartbeats
            .fetch_add(count as u64, Ordering::Relaxed);
        Ok(count)
    }

    fn mutate_lease(
        &self,
        state: &mut State,
        resource: &str,
        owner: &str,
        f: impl FnOnce(&mut Lease),
    ) -> Result<Lease> {
        let leases = state
            .leases
            .get_mut(resource)
            .ok_or_else(|| Error::NotHeld {
                resource: resource.into(),
                owner: owner.into(),
            })?;
        let lease = leases
            .iter_mut()
            .find(|l| l.owner == owner)
            .ok_or_else(|| Error::NotHeld {
                resource: resource.into(),
                owner: owner.into(),
            })?;
        f(lease);
        let lease = lease.clone();
        self.store.put_lease(&lease)?;
        Ok(lease)
    }

    // ------------------------------------------------------------------
    // Transfer & steal
    // ------------------------------------------------------------------

    /// Hand a lease to a new owner without releasing it.
    pub fn transfer(&self, resource: &str, from: &str, to: &str) -> Result<Lease> {
        let resource = hierarchy::normalize(resource);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let to_held = state
            .leases
            .get(&resource)
            .map(|ls| ls.iter().any(|l| l.owner == to))
            .unwrap_or(false);
        if to_held {
            return Err(Error::Invalid(format!(
                "'{to}' already holds a lease on '{resource}'"
            )));
        }
        let lease = self.mutate_lease(&mut state, &resource, from, |lease| {
            lease.owner = to.to_string();
            lease.last_heartbeat = now_ms();
        })?;
        self.store.put_owner(to, &serde_json::json!({}))?;
        self.metrics.transfers.fetch_add(1, Ordering::Relaxed);
        self.store.append_audit(
            &AuditRecord::new(to, "transfer", &resource)
                .with_metadata(serde_json::json!({ "from": from })),
        )?;
        self.bus.lock().unwrap_or_else(|e| e.into_inner()).emit(
            EventKind::OwnerTransferred,
            &resource,
            to,
            serde_json::json!({ "from": from }),
        );
        Ok(lease)
    }

    /// Forcibly take a resource: every other owner's lease on it is revoked
    /// and an exclusive lease is granted to `new_owner`.
    pub fn steal(&self, resource: &str, new_owner: &str, reason: &str) -> Result<Lease> {
        let resource = hierarchy::normalize(resource);
        let now = now_ms();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let victims: Vec<Lease> = state
            .leases
            .get(&resource)
            .map(|ls| {
                ls.iter()
                    .filter(|l| l.owner != new_owner)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        if victims.is_empty() {
            return Err(Error::NotFound(format!(
                "no lease to steal on '{resource}'"
            )));
        }
        for victim in &victims {
            self.remove_lease_inner(&mut state, &resource, &victim.owner, "stolen")?;
        }
        self.metrics.steals.fetch_add(1, Ordering::Relaxed);
        let req = AcquireRequest::new(&resource, new_owner, LockMode::Exclusive)
            .metadata(serde_json::json!({ "stolen": true, "reason": reason }));
        let lease = self.grant(&mut state, &req, &resource, now)?;
        self.store.append_audit(
            &AuditRecord::new(new_owner, "steal", &resource).with_metadata(serde_json::json!({
                "reason": reason,
                "victims": victims.iter().map(|v| v.owner.clone()).collect::<Vec<_>>(),
            })),
        )?;
        self.bus.lock().unwrap_or_else(|e| e.into_inner()).emit(
            EventKind::LockStolen,
            &resource,
            new_owner,
            serde_json::json!({
                "reason": reason,
                "victims": victims.iter().map(|v| v.owner.clone()).collect::<Vec<_>>(),
            }),
        );
        Ok(lease)
    }

    // ------------------------------------------------------------------
    // Promote & downgrade
    // ------------------------------------------------------------------

    /// Strengthen a held lease (Shared/Intent -> Exclusive by default).
    pub fn promote(&self, resource: &str, owner: &str, mode: Option<LockMode>) -> Result<Lease> {
        let resource = hierarchy::normalize(resource);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let current = state
            .leases
            .get(&resource)
            .and_then(|ls| ls.iter().find(|l| l.owner == owner))
            .cloned()
            .ok_or_else(|| Error::NotHeld {
                resource: resource.clone(),
                owner: owner.into(),
            })?;
        let target = mode.unwrap_or(LockMode::Exclusive);
        if strength(target) <= strength(current.mode) {
            return Err(Error::Invalid(format!(
                "cannot promote {} to {}",
                current.mode.as_str(),
                target.as_str()
            )));
        }
        if let Some(reason) = state.find_conflict(&resource, owner, target) {
            self.metrics.conflicts.fetch_add(1, Ordering::Relaxed);
            return Err(Error::Conflict { resource, reason });
        }
        self.upgrade_mode(&mut state, &resource, owner, target)
    }

    /// Weaken a held lease (Exclusive -> Shared by default). May unblock
    /// queued waiters.
    pub fn downgrade(
        &self,
        resource: &str,
        owner: &str,
        mode: Option<LockMode>,
    ) -> Result<Vec<Lease>> {
        let resource = hierarchy::normalize(resource);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let target = mode.unwrap_or(LockMode::Shared);
        let current = state
            .leases
            .get(&resource)
            .and_then(|ls| ls.iter().find(|l| l.owner == owner))
            .cloned()
            .ok_or_else(|| Error::NotHeld {
                resource: resource.clone(),
                owner: owner.into(),
            })?;
        if strength(target) >= strength(current.mode) {
            return Err(Error::Invalid(format!(
                "cannot downgrade {} to {}",
                current.mode.as_str(),
                target.as_str()
            )));
        }
        let lease = self.mutate_lease(&mut state, &resource, owner, |l| l.mode = target)?;
        self.metrics.downgrades.fetch_add(1, Ordering::Relaxed);
        self.store.append_audit(
            &AuditRecord::new(owner, "downgrade", &resource)
                .with_metadata(serde_json::json!({ "mode": target.as_str() })),
        )?;
        self.bus.lock().unwrap_or_else(|e| e.into_inner()).emit(
            EventKind::LockDowngraded,
            &resource,
            owner,
            serde_json::json!({ "mode": target.as_str(), "lease_id": lease.id }),
        );
        self.promote_related(&mut state, &resource)
    }

    // ------------------------------------------------------------------
    // Expiry sweep & queue promotion
    // ------------------------------------------------------------------

    /// Expire leases whose lease time or heartbeat timeout has elapsed,
    /// then advance affected queues.
    pub fn sweep(&self) -> Result<SweepReport> {
        let now = now_ms();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut report = SweepReport::default();
        let mut affected: Vec<ResourceId> = Vec::new();

        let resources: Vec<ResourceId> = state.leases.keys().cloned().collect();
        for resource in resources {
            let Some(leases) = state.leases.get_mut(&resource) else {
                continue;
            };
            let mut i = 0;
            while i < leases.len() {
                let lease = &leases[i];
                let (dead, missed) = (lease.is_expired(now), lease.heartbeat_missed(now));
                if !dead && !missed {
                    i += 1;
                    continue;
                }
                let lease = leases.remove(i);
                self.store.remove_lease(&lease.resource, &lease.owner)?;
                self.metrics.expirations.fetch_add(1, Ordering::Relaxed);
                let kind = if missed && !dead {
                    EventKind::HeartbeatMissed
                } else {
                    EventKind::LeaseExpired
                };
                self.store.append_audit(
                    &AuditRecord::new(&lease.owner, "expire", &lease.resource)
                        .with_metadata(serde_json::json!({ "heartbeat_missed": missed })),
                )?;
                self.bus.lock().unwrap_or_else(|e| e.into_inner()).emit(
                    kind,
                    &lease.resource,
                    &lease.owner,
                    serde_json::json!({ "mode": lease.mode.as_str() }),
                );
                report.expired.push(lease);
                affected.push(resource.clone());
            }
            if state
                .leases
                .get(&resource)
                .map(|l| l.is_empty())
                .unwrap_or(false)
            {
                state.leases.remove(&resource);
            }
        }

        for resource in affected {
            let promoted = self.promote_related(&mut state, &resource)?;
            report.promoted.extend(promoted);
        }
        Ok(report)
    }

    /// Promote queued waiters on `resource` and all related resources
    /// (ancestors and descendants) whose conflict situation may have changed.
    fn promote_related(&self, state: &mut State, resource: &str) -> Result<Vec<Lease>> {
        let mut targets: Vec<ResourceId> = vec![resource.to_string()];
        targets.extend(hierarchy::ancestors(resource));
        for queued in state.queue.keys() {
            if (hierarchy::is_ancestor(resource, queued)
                || hierarchy::is_ancestor(queued, resource))
                && !targets.contains(queued)
            {
                targets.push(queued.clone());
            }
        }
        let mut promoted = Vec::new();
        for target in targets {
            promoted.extend(self.promote_queue(state, &target)?);
        }
        Ok(promoted)
    }

    /// Greedily grant queued waiters in policy order until no more fit.
    // The loop re-reads `state.queue` after every grant; a `while let` would
    // hold the borrow across mutations.
    #[allow(clippy::while_let_loop)]
    fn promote_queue(&self, state: &mut State, resource: &str) -> Result<Vec<Lease>> {
        let mut promoted = Vec::new();
        loop {
            let Some(entries) = state.queue.get(resource) else {
                break;
            };
            if entries.is_empty() {
                state.queue.remove(resource);
                break;
            }
            let order: Vec<QueueEntryId> = self
                .config
                .queue_policy
                .ordered(entries)
                .iter()
                .map(|e| e.id)
                .collect();
            let mut granted_any = false;
            for id in order {
                let entry = match state
                    .queue
                    .get(resource)
                    .and_then(|es| es.iter().find(|e| e.id == id))
                {
                    Some(e) => e.clone(),
                    None => continue,
                };
                if state
                    .find_conflict(resource, &entry.owner, entry.mode)
                    .is_some()
                {
                    continue;
                }
                // Remove from queue, grant (or upgrade in place for a
                // reentrant waiter strengthening its own lease).
                if let Some(entries) = state.queue.get_mut(resource) {
                    entries.retain(|e| e.id != id);
                }
                self.store.remove_queue_entry(id)?;
                let now = now_ms();
                let lease = if state
                    .leases
                    .get(resource)
                    .map(|ls| ls.iter().any(|l| l.owner == entry.owner))
                    .unwrap_or(false)
                {
                    self.upgrade_mode(state, resource, &entry.owner, entry.mode)?
                } else {
                    let req = AcquireRequest::new(resource, &entry.owner, entry.mode)
                        .priority(entry.priority)
                        .lease_ms(entry.lease_duration_ms)
                        .metadata(entry.metadata.clone());
                    self.grant(state, &req, resource, now)?
                };
                self.metrics
                    .queue_promotions
                    .fetch_add(1, Ordering::Relaxed);
                self.bus.lock().unwrap_or_else(|e| e.into_inner()).emit(
                    EventKind::QueueExited,
                    resource,
                    &entry.owner,
                    serde_json::json!({ "granted": true }),
                );
                promoted.push(lease);
                granted_any = true;
            }
            if !granted_any {
                break;
            }
        }
        Ok(promoted)
    }

    fn queue_position(&self, state: &State, resource: &str, id: QueueEntryId) -> usize {
        let Some(entries) = state.queue.get(resource) else {
            return 0;
        };
        let ordered = self.config.queue_policy.ordered(entries);
        ordered
            .iter()
            .position(|e| e.id == id)
            .map(|p| p + 1)
            .unwrap_or(0)
    }

    // ------------------------------------------------------------------
    // Inspection
    // ------------------------------------------------------------------

    pub fn inspect(&self, resource: &str) -> ResourceView {
        let resource = hierarchy::normalize(resource);
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let leases = state.leases.get(&resource).cloned().unwrap_or_default();
        let queue = state
            .queue
            .get(&resource)
            .map(|entries| {
                self.config
                    .queue_policy
                    .ordered(entries)
                    .iter()
                    .map(|e| (*e).clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut ancestor_locks = Vec::new();
        for anc in hierarchy::ancestors(&resource) {
            if let Some(ls) = state.leases.get(&anc) {
                ancestor_locks.extend(ls.iter().cloned());
            }
        }
        let mut descendant_locks = Vec::new();
        for (res, ls) in &state.leases {
            if hierarchy::is_ancestor(&resource, res) {
                descendant_locks.extend(ls.iter().cloned());
            }
        }
        ResourceView {
            resource,
            leases,
            queue,
            ancestor_locks,
            descendant_locks,
        }
    }

    /// All active leases across all resources.
    pub fn leases(&self) -> Vec<Lease> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.leases.values().flatten().cloned().collect()
    }

    /// Current queue for a resource, in policy order.
    pub fn queue(&self, resource: &str) -> Vec<QueueEntry> {
        self.inspect(resource).queue
    }

    // ------------------------------------------------------------------
    // Events, audit, metrics
    // ------------------------------------------------------------------

    pub fn subscribe(&self) -> mpsc::Receiver<Event> {
        self.bus
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .subscribe()
    }

    pub fn events(&self, limit: usize) -> Vec<Event> {
        self.bus
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tail(limit)
    }

    pub fn audit_tail(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        self.store.audit_tail(limit)
    }

    pub fn metrics(&self) -> MetricsSnapshot {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let m = &self.metrics;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        MetricsSnapshot {
            acquires: get(&m.acquires),
            grants: get(&m.grants),
            queued: get(&m.queued),
            releases: get(&m.releases),
            renewals: get(&m.renewals),
            heartbeats: get(&m.heartbeats),
            expirations: get(&m.expirations),
            steals: get(&m.steals),
            transfers: get(&m.transfers),
            promotions: get(&m.promotions),
            downgrades: get(&m.downgrades),
            conflicts: get(&m.conflicts),
            queue_promotions: get(&m.queue_promotions),
            active_leases: state.total_leases(),
            queue_depth: state.total_queued(),
        }
    }

    pub fn queue_policy(&self) -> QueuePolicy {
        self.config.queue_policy
    }

    // ------------------------------------------------------------------
    // Id allocation (persisted counters)
    // ------------------------------------------------------------------

    fn alloc_lease_id(&self, state: &mut State) -> Result<LeaseId> {
        let id = state.next_lease_id;
        state.next_lease_id += 1;
        self.store.set_counter("lease_id", state.next_lease_id)?;
        Ok(id)
    }

    fn alloc_queue_id(&self, state: &mut State) -> Result<QueueEntryId> {
        let id = state.next_queue_id;
        state.next_queue_id += 1;
        self.store.set_counter("queue_id", state.next_queue_id)?;
        Ok(id)
    }

    fn alloc_seq(&self, state: &mut State) -> Result<u64> {
        let seq = state.next_seq;
        state.next_seq += 1;
        self.store.set_counter("seq", state.next_seq)?;
        Ok(seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryStore;

    fn manager() -> LockManager<InMemoryStore> {
        LockManager::new(InMemoryStore::new(), Config::default()).unwrap()
    }

    fn acquire(
        m: &LockManager<InMemoryStore>,
        resource: &str,
        owner: &str,
        mode: LockMode,
    ) -> AcquireOutcome {
        m.acquire(AcquireRequest::new(resource, owner, mode))
            .unwrap()
    }

    #[test]
    fn exclusive_conflict_queues_then_promotes() {
        let m = manager();
        assert!(matches!(
            acquire(&m, "file:/src/main.rs", "hermes", LockMode::Exclusive),
            AcquireOutcome::Granted { .. }
        ));
        let queued = acquire(&m, "file:/src/main.rs", "openclaw", LockMode::Exclusive);
        assert!(matches!(queued, AcquireOutcome::Queued { position: 1, .. }));

        let promoted = m.release("file:/src/main.rs", "hermes").unwrap();
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].owner, "openclaw");

        let view = m.inspect("file:/src/main.rs");
        assert_eq!(view.leases.len(), 1);
        assert_eq!(view.leases[0].owner, "openclaw");
        assert!(view.queue.is_empty());
    }

    #[test]
    fn shared_leases_coexist() {
        let m = manager();
        assert!(matches!(
            acquire(&m, "docs", "a", LockMode::Shared),
            AcquireOutcome::Granted { .. }
        ));
        assert!(matches!(
            acquire(&m, "docs", "b", LockMode::Shared),
            AcquireOutcome::Granted { .. }
        ));
        assert_eq!(m.inspect("docs").leases.len(), 2);
    }

    #[test]
    fn intent_compatibility() {
        let m = manager();
        assert!(matches!(
            acquire(&m, "db:main", "a", LockMode::Intent),
            AcquireOutcome::Granted { .. }
        ));
        // Shared is compatible with Intent.
        assert!(matches!(
            acquire(&m, "db:main", "b", LockMode::Shared),
            AcquireOutcome::Granted { .. }
        ));
        // Exclusive is not.
        assert!(matches!(
            acquire(&m, "db:main", "c", LockMode::Exclusive),
            AcquireOutcome::Queued { .. }
        ));
    }

    #[test]
    fn hierarchy_exclusive_ancestor_blocks_descendant() {
        let m = manager();
        acquire(&m, "workspace", "hermes", LockMode::Exclusive);
        assert!(matches!(
            acquire(&m, "workspace/frontend", "openclaw", LockMode::Exclusive),
            AcquireOutcome::Queued { .. }
        ));
        assert!(matches!(
            acquire(&m, "workspace/frontend", "openclaw", LockMode::Shared),
            AcquireOutcome::Queued { .. }
        ));
        // Sibling subtree is unaffected.
        assert!(matches!(
            acquire(&m, "other/sub", "openclaw", LockMode::Exclusive),
            AcquireOutcome::Granted { .. }
        ));
    }

    #[test]
    fn hierarchy_shared_ancestor_blocks_exclusive_descendant_only() {
        let m = manager();
        acquire(&m, "workspace", "a", LockMode::Shared);
        assert!(matches!(
            acquire(&m, "workspace/frontend", "b", LockMode::Shared),
            AcquireOutcome::Granted { .. }
        ));
        assert!(matches!(
            acquire(&m, "workspace/frontend", "c", LockMode::Exclusive),
            AcquireOutcome::Queued { .. }
        ));
        assert!(matches!(
            acquire(&m, "workspace/frontend", "d", LockMode::Intent),
            AcquireOutcome::Queued { .. }
        ));
    }

    #[test]
    fn descendant_exclusive_blocks_ancestor_exclusive() {
        let m = manager();
        acquire(&m, "workspace/frontend/button.rs", "a", LockMode::Exclusive);
        assert!(matches!(
            acquire(&m, "workspace", "b", LockMode::Exclusive),
            AcquireOutcome::Queued { .. }
        ));
        // Releasing the descendant promotes the queued ancestor lock.
        m.release("workspace/frontend/button.rs", "a").unwrap();
        let view = m.inspect("workspace");
        assert_eq!(view.leases.len(), 1);
        assert_eq!(view.leases[0].owner, "b");
    }

    #[test]
    fn reentrant_acquire_returns_held() {
        let m = manager();
        acquire(&m, "gpu:0", "agent", LockMode::Exclusive);
        let again = acquire(&m, "gpu:0", "agent", LockMode::Shared);
        assert!(matches!(again, AcquireOutcome::Held { .. }));
        // Stronger reacquire upgrades in place when uncontested.
        let up = acquire(&m, "task:1", "agent", LockMode::Shared);
        assert!(matches!(up, AcquireOutcome::Granted { .. }));
        let up2 = acquire(&m, "task:1", "agent", LockMode::Exclusive);
        assert!(matches!(up2, AcquireOutcome::Granted { .. }));
        assert_eq!(m.inspect("task:1").leases[0].mode, LockMode::Exclusive);
    }

    #[test]
    fn lease_expiry_promotes_queue() {
        let m = LockManager::new(
            InMemoryStore::new(),
            Config {
                default_lease_ms: 0,
                ..Config::default()
            },
        )
        .unwrap();
        acquire(&m, "r", "a", LockMode::Exclusive);
        acquire(&m, "r", "b", LockMode::Exclusive);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let report = m.sweep().unwrap();
        assert_eq!(report.expired.len(), 1);
        assert_eq!(report.promoted.len(), 1);
        assert_eq!(report.promoted[0].owner, "b");
    }

    #[test]
    fn heartbeat_timeout_expires_lease() {
        let m = LockManager::new(
            InMemoryStore::new(),
            Config {
                default_lease_ms: 60_000,
                default_heartbeat_timeout_ms: 1,
                ..Config::default()
            },
        )
        .unwrap();
        acquire(&m, "r", "a", LockMode::Exclusive);
        std::thread::sleep(std::time::Duration::from_millis(3));
        let report = m.sweep().unwrap();
        assert_eq!(report.expired.len(), 1);
        let events = m.events(10);
        assert!(events.iter().any(|e| e.kind == EventKind::HeartbeatMissed));
    }

    #[test]
    fn heartbeat_keeps_lease_alive() {
        let m = LockManager::new(
            InMemoryStore::new(),
            Config {
                default_lease_ms: 60_000,
                default_heartbeat_timeout_ms: 30,
                ..Config::default()
            },
        )
        .unwrap();
        acquire(&m, "r", "a", LockMode::Exclusive);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(m.heartbeat("a", None).unwrap(), 1);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(m.sweep().unwrap().expired.is_empty());
    }

    #[test]
    fn renew_extends_expiry() {
        let m = manager();
        acquire(&m, "r", "a", LockMode::Exclusive);
        let before = m.inspect("r").leases[0].expires_at;
        std::thread::sleep(std::time::Duration::from_millis(2));
        let renewed = m.renew("r", "a").unwrap();
        assert!(renewed.expires_at > before);
    }

    #[test]
    fn transfer_changes_owner_without_unlock() {
        let m = manager();
        acquire(&m, "r", "hermes", LockMode::Exclusive);
        let lease = m.transfer("r", "hermes", "openclaw").unwrap();
        assert_eq!(lease.owner, "openclaw");
        assert!(m.release("r", "hermes").is_err());
        m.release("r", "openclaw").unwrap();
    }

    #[test]
    fn steal_revokes_victim() {
        let m = manager();
        acquire(&m, "deploy:prod", "stuck-agent", LockMode::Exclusive);
        let lease = m
            .steal("deploy:prod", "admin", "agent unresponsive")
            .unwrap();
        assert_eq!(lease.owner, "admin");
        assert_eq!(lease.mode, LockMode::Exclusive);
        assert!(m.release("deploy:prod", "stuck-agent").is_err());
        let metrics = m.metrics();
        assert_eq!(metrics.steals, 1);
    }

    #[test]
    fn promote_and_downgrade() {
        let m = manager();
        acquire(&m, "r", "a", LockMode::Shared);
        acquire(&m, "r", "b", LockMode::Shared);
        // Promote blocked while another reader holds the resource.
        assert!(m.promote("r", "a", None).is_err());
        m.release("r", "b").unwrap();
        let lease = m.promote("r", "a", None).unwrap();
        assert_eq!(lease.mode, LockMode::Exclusive);
        // Downgrade lets queued shared waiters in.
        acquire(&m, "r", "c", LockMode::Shared);
        assert!(matches!(
            acquire(&m, "r", "c", LockMode::Shared),
            AcquireOutcome::Queued { .. }
        ));
        let promoted = m.downgrade("r", "a", None).unwrap();
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].owner, "c");
    }

    #[test]
    fn priority_queue_ordering() {
        let m = LockManager::new(
            InMemoryStore::new(),
            Config {
                queue_policy: QueuePolicy::Priority,
                ..Config::default()
            },
        )
        .unwrap();
        acquire(&m, "r", "holder", LockMode::Exclusive);
        m.acquire(AcquireRequest::new("r", "low", LockMode::Exclusive).priority(Priority::Low))
            .unwrap();
        m.acquire(
            AcquireRequest::new("r", "critical", LockMode::Exclusive).priority(Priority::Critical),
        )
        .unwrap();
        let promoted = m.release("r", "holder").unwrap();
        assert_eq!(promoted[0].owner, "critical");
    }

    #[test]
    fn audit_log_records_actions() {
        let m = manager();
        acquire(&m, "r", "a", LockMode::Exclusive);
        m.release("r", "a").unwrap();
        let audit = m.audit_tail(10).unwrap();
        let actions: Vec<&str> = audit.iter().map(|r| r.action.as_str()).collect();
        assert!(actions.contains(&"acquire"));
        assert!(actions.contains(&"release"));
    }

    #[test]
    fn inspect_reports_queue_and_hierarchy() {
        let m = manager();
        acquire(&m, "workspace", "a", LockMode::Exclusive);
        acquire(&m, "workspace/frontend", "b", LockMode::Exclusive);
        acquire(&m, "workspace/frontend", "c", LockMode::Exclusive);
        let view = m.inspect("workspace/frontend");
        assert!(view.leases.is_empty());
        assert_eq!(view.queue.len(), 2);
        assert_eq!(view.ancestor_locks.len(), 1);
        assert_eq!(view.ancestor_locks[0].owner, "a");
    }
}
