//! Queue scheduling policies.

use serde::{Deserialize, Serialize};
use std::cmp::Reverse;

use crate::types::QueueEntry;

/// How waiting owners are ordered when a lease becomes available.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueuePolicy {
    /// First in, first out (sequence order).
    #[default]
    Fifo,
    /// Highest priority first, FIFO within a priority level.
    Priority,
    /// Shortest requested lease first.
    ShortestLease,
    /// Longest-waiting owner first (by request timestamp).
    OldestWaiting,
    /// Weighted fair: priority acts as weight, FIFO within a weight class.
    WeightedFair,
}

impl QueuePolicy {
    pub fn parse(s: &str) -> Option<QueuePolicy> {
        match s {
            "fifo" => Some(QueuePolicy::Fifo),
            "priority" => Some(QueuePolicy::Priority),
            "shortest_lease" | "shortest-lease" => Some(QueuePolicy::ShortestLease),
            "oldest_waiting" | "oldest-waiting" => Some(QueuePolicy::OldestWaiting),
            "weighted_fair" | "weighted-fair" => Some(QueuePolicy::WeightedFair),
            _ => None,
        }
    }

    /// Order queue entries according to the policy. The result is the
    /// promotion order candidates are considered in.
    pub fn ordered<'a>(&self, entries: &'a [QueueEntry]) -> Vec<&'a QueueEntry> {
        let mut v: Vec<&QueueEntry> = entries.iter().collect();
        match self {
            QueuePolicy::Fifo => v.sort_by_key(|e| e.seq),
            QueuePolicy::OldestWaiting => v.sort_by_key(|e| (e.requested_at, e.seq)),
            QueuePolicy::Priority => v.sort_by_key(|e| (Reverse(e.priority), e.seq)),
            QueuePolicy::ShortestLease => v.sort_by_key(|e| (e.lease_duration_ms, e.seq)),
            QueuePolicy::WeightedFair => v.sort_by_key(|e| (Reverse(e.priority as u64), e.seq)),
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{LockMode, OwnerId, Priority};

    fn entry(seq: u64, owner: &str, priority: Priority, lease_ms: u64, requested_at: u64) -> QueueEntry {
        QueueEntry {
            id: seq,
            seq,
            resource: "r".into(),
            owner: OwnerId::from(owner),
            mode: LockMode::Exclusive,
            priority,
            requested_at,
            lease_duration_ms: lease_ms,
            heartbeat_interval_ms: 30_000,
            heartbeat_timeout_ms: 90_000,
            capabilities: vec![],
            metadata: serde_json::json!({}),
        }
    }

    #[test]
    fn priority_policy_orders_by_priority_then_seq() {
        let entries = vec![
            entry(1, "low", Priority::Low, 100, 100),
            entry(2, "high", Priority::High, 100, 200),
            entry(3, "high2", Priority::High, 100, 300),
        ];
        let ordered = QueuePolicy::Priority.ordered(&entries);
        let owners: Vec<&str> = ordered.iter().map(|e| e.owner.as_str()).collect();
        assert_eq!(owners, vec!["high", "high2", "low"]);
    }

    #[test]
    fn shortest_lease_policy() {
        let entries = vec![
            entry(1, "long", Priority::Normal, 5000, 100),
            entry(2, "short", Priority::Normal, 100, 200),
        ];
        let ordered = QueuePolicy::ShortestLease.ordered(&entries);
        assert_eq!(ordered[0].owner, "short");
    }

    #[test]
    fn fifo_policy() {
        let entries = vec![
            entry(7, "second", Priority::Critical, 100, 50),
            entry(3, "first", Priority::Low, 9999, 10),
        ];
        let ordered = QueuePolicy::Fifo.ordered(&entries);
        assert_eq!(ordered[0].owner, "first");
    }
}
