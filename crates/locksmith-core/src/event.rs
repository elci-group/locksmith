//! Event bus: every state transition in the lock manager emits an event.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::mpsc;

use crate::types::{OwnerId, ResourceId, TimestampMs, now_ms};

/// The kind of state transition an event describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    LockAcquired,
    LockReleased,
    LeaseExpired,
    HeartbeatMissed,
    OwnerTransferred,
    ConflictDetected,
    QueueEntered,
    QueueExited,
    LockRenewed,
    Heartbeat,
    LockStolen,
    LockPromoted,
    LockDowngraded,
    RecoveryCompleted,
}

/// A single emitted event. `seq` is a monotonic per-process sequence number.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub ts: TimestampMs,
    pub kind: EventKind,
    pub resource: ResourceId,
    pub owner: OwnerId,
    #[serde(default)]
    pub detail: serde_json::Value,
}

/// In-process event bus with a bounded ring buffer and subscriber channels.
pub struct EventBus {
    seq: u64,
    buffer: VecDeque<Event>,
    capacity: usize,
    subscribers: Vec<mpsc::Sender<Event>>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        EventBus {
            seq: 0,
            buffer: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
            subscribers: Vec::new(),
        }
    }

    pub fn emit(
        &mut self,
        kind: EventKind,
        resource: impl Into<ResourceId>,
        owner: impl Into<OwnerId>,
        detail: serde_json::Value,
    ) {
        self.seq += 1;
        let event = Event {
            seq: self.seq,
            ts: now_ms(),
            kind,
            resource: resource.into(),
            owner: owner.into(),
            detail,
        };
        if self.buffer.len() >= self.capacity {
            self.buffer.pop_front();
        }
        self.buffer.push_back(event.clone());
        // Drop dead subscribers.
        self.subscribers.retain(|tx| tx.send(event.clone()).is_ok());
    }

    /// Subscribe to future events.
    pub fn subscribe(&mut self) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel();
        self.subscribers.push(tx);
        rx
    }

    /// The most recent `limit` events, oldest first.
    pub fn tail(&self, limit: usize) -> Vec<Event> {
        let skip = self.buffer.len().saturating_sub(limit);
        self.buffer.iter().skip(skip).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}
