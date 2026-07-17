//! SQLite persistence: the default, durable store.
//!
//! Schema (per the technical directive): `leases`, `owners`, `resources`,
//! `queue`, `audit`, `sessions` — plus a small `counters` table so id
//! sequences survive restarts.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::audit::AuditRecord;
use crate::error::{Error, Result};
use crate::types::{now_ms, Lease, LeaseCapability, LockMode, Priority, QueueEntry, QueueEntryId};

use super::{Snapshot, Store};

pub struct SqliteStore {
    conn: Mutex<Connection>,
}

fn mode_to_str(mode: LockMode) -> &'static str {
    match mode {
        LockMode::Shared => "shared",
        LockMode::Exclusive => "exclusive",
        LockMode::Intent => "intent",
    }
}

fn mode_from_str(s: &str) -> Result<LockMode> {
    LockMode::parse(s).ok_or_else(|| Error::Store(format!("unknown lock mode '{s}'")))
}

fn caps_to_json(caps: &[LeaseCapability]) -> String {
    serde_json::to_string(caps).unwrap_or_else(|_| "[]".to_string())
}

fn caps_from_json(s: &str) -> Vec<LeaseCapability> {
    serde_json::from_str(s).unwrap_or_default()
}

fn meta_to_json(meta: &serde_json::Value) -> String {
    serde_json::to_string(meta).unwrap_or_else(|_| "{}".to_string())
}

fn meta_from_json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or_else(|_| serde_json::json!({}))
}

impl SqliteStore {
    /// Open (creating if necessary) a database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Open a purely in-memory database (useful for tests).
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;

             CREATE TABLE IF NOT EXISTS leases (
                 resource              TEXT NOT NULL,
                 owner                 TEXT NOT NULL,
                 id                    INTEGER NOT NULL,
                 mode                  TEXT NOT NULL,
                 priority              INTEGER NOT NULL,
                 acquired_at           INTEGER NOT NULL,
                 expires_at            INTEGER NOT NULL,
                 lease_duration_ms     INTEGER NOT NULL,
                 last_heartbeat        INTEGER NOT NULL,
                 heartbeat_interval_ms INTEGER NOT NULL,
                 heartbeat_timeout_ms  INTEGER NOT NULL,
                 epoch                 INTEGER NOT NULL DEFAULT 0,
                 capabilities          TEXT NOT NULL,
                 metadata              TEXT NOT NULL,
                 PRIMARY KEY (resource, owner)
             );

             CREATE TABLE IF NOT EXISTS queue (
                 id                    INTEGER PRIMARY KEY,
                 seq                   INTEGER NOT NULL,
                 resource              TEXT NOT NULL,
                 owner                 TEXT NOT NULL,
                 mode                  TEXT NOT NULL,
                 priority              INTEGER NOT NULL,
                 requested_at          INTEGER NOT NULL,
                 lease_duration_ms     INTEGER NOT NULL,
                 heartbeat_interval_ms INTEGER NOT NULL,
                 heartbeat_timeout_ms  INTEGER NOT NULL,
                 capabilities          TEXT NOT NULL,
                 metadata              TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_queue_resource ON queue(resource, seq);

             CREATE TABLE IF NOT EXISTS resources (
                 id         TEXT PRIMARY KEY,
                 kind       TEXT NOT NULL,
                 metadata   TEXT NOT NULL,
                 created_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS owners (
                 name       TEXT PRIMARY KEY,
                 metadata   TEXT NOT NULL,
                 first_seen INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS audit (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts          INTEGER NOT NULL,
                 owner       TEXT NOT NULL,
                 action      TEXT NOT NULL,
                 resource    TEXT NOT NULL,
                 duration_ms INTEGER,
                 metadata    TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
             CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit(resource);

             CREATE TABLE IF NOT EXISTS sessions (
                 id         TEXT PRIMARY KEY,
                 owner      TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL,
                 metadata   TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS counters (
                 key   TEXT PRIMARY KEY,
                 value INTEGER NOT NULL
             );",
        )?;
        // Migration: databases created before fencing tokens lack the
        // per-lease epoch column.
        let has_epoch = {
            let mut stmt = conn.prepare("PRAGMA table_info(leases)")?;
            let names = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            names.iter().any(|n| n == "epoch")
        };
        if !has_epoch {
            conn.execute_batch("ALTER TABLE leases ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0")?;
        }
        Ok(SqliteStore {
            conn: Mutex::new(conn),
        })
    }

    fn lease_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Lease> {
        let mode_str: String = row.get("mode")?;
        let caps_str: String = row.get("capabilities")?;
        let meta_str: String = row.get("metadata")?;
        Ok(Lease {
            id: row.get("id")?,
            resource: row.get("resource")?,
            owner: row.get("owner")?,
            mode: mode_from_str(&mode_str).unwrap_or(LockMode::Exclusive),
            priority: Priority::try_from(row.get::<_, i64>("priority")?).unwrap_or_default(),
            acquired_at: row.get("acquired_at")?,
            expires_at: row.get("expires_at")?,
            lease_duration_ms: row.get("lease_duration_ms")?,
            last_heartbeat: row.get("last_heartbeat")?,
            heartbeat_interval_ms: row.get("heartbeat_interval_ms")?,
            heartbeat_timeout_ms: row.get("heartbeat_timeout_ms")?,
            epoch: row.get::<_, i64>("epoch")? as u64,
            // Monotonic anchors are re-derived from the wall-clock fields by
            // `Lease::reanchor` when the manager replays this snapshot.
            deadline: std::time::Instant::now(),
            last_beat: std::time::Instant::now(),
            capabilities: caps_from_json(&caps_str),
            metadata: meta_from_json(&meta_str),
        })
    }

    fn queue_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<QueueEntry> {
        let mode_str: String = row.get("mode")?;
        let caps_str: String = row.get("capabilities")?;
        let meta_str: String = row.get("metadata")?;
        Ok(QueueEntry {
            id: row.get("id")?,
            seq: row.get("seq")?,
            resource: row.get("resource")?,
            owner: row.get("owner")?,
            mode: mode_from_str(&mode_str).unwrap_or(LockMode::Exclusive),
            priority: Priority::try_from(row.get::<_, i64>("priority")?).unwrap_or_default(),
            requested_at: row.get("requested_at")?,
            lease_duration_ms: row.get("lease_duration_ms")?,
            heartbeat_interval_ms: row.get("heartbeat_interval_ms")?,
            heartbeat_timeout_ms: row.get("heartbeat_timeout_ms")?,
            capabilities: caps_from_json(&caps_str),
            metadata: meta_from_json(&meta_str),
        })
    }
}

impl TryFrom<i64> for Priority {
    type Error = ();

    fn try_from(v: i64) -> std::result::Result<Self, ()> {
        match v {
            0 => Ok(Priority::Low),
            1 => Ok(Priority::Normal),
            2 => Ok(Priority::High),
            3 => Ok(Priority::Critical),
            _ => Err(()),
        }
    }
}

impl Store for SqliteStore {
    fn put_lease(&self, lease: &Lease) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO leases
             (resource, owner, id, mode, priority, acquired_at, expires_at,
              lease_duration_ms, last_heartbeat, heartbeat_interval_ms,
              heartbeat_timeout_ms, epoch, capabilities, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                lease.resource,
                lease.owner,
                lease.id as i64,
                mode_to_str(lease.mode),
                lease.priority as i64,
                lease.acquired_at as i64,
                lease.expires_at as i64,
                lease.lease_duration_ms as i64,
                lease.last_heartbeat as i64,
                lease.heartbeat_interval_ms as i64,
                lease.heartbeat_timeout_ms as i64,
                lease.epoch as i64,
                caps_to_json(&lease.capabilities),
                meta_to_json(&lease.metadata),
            ],
        )?;
        Ok(())
    }

    fn remove_lease(&self, resource: &str, owner: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "DELETE FROM leases WHERE resource = ?1 AND owner = ?2",
            params![resource, owner],
        )?;
        Ok(())
    }

    fn put_queue_entry(&self, entry: &QueueEntry) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO queue
             (id, seq, resource, owner, mode, priority, requested_at,
              lease_duration_ms, heartbeat_interval_ms, heartbeat_timeout_ms,
              capabilities, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                entry.id as i64,
                entry.seq as i64,
                entry.resource,
                entry.owner,
                mode_to_str(entry.mode),
                entry.priority as i64,
                entry.requested_at as i64,
                entry.lease_duration_ms as i64,
                entry.heartbeat_interval_ms as i64,
                entry.heartbeat_timeout_ms as i64,
                caps_to_json(&entry.capabilities),
                meta_to_json(&entry.metadata),
            ],
        )?;
        Ok(())
    }

    fn remove_queue_entry(&self, id: QueueEntryId) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("DELETE FROM queue WHERE id = ?1", params![id as i64])?;
        Ok(())
    }

    fn put_resource(&self, id: &str, kind: &str, metadata: &serde_json::Value) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO resources (id, kind, metadata, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, metadata = excluded.metadata",
            params![id, kind, meta_to_json(metadata), now_ms() as i64],
        )?;
        Ok(())
    }

    fn put_owner(&self, name: &str, metadata: &serde_json::Value) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO owners (name, metadata, first_seen)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET metadata = excluded.metadata",
            params![name, meta_to_json(metadata), now_ms() as i64],
        )?;
        Ok(())
    }

    fn append_audit(&self, record: &AuditRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO audit (ts, owner, action, resource, duration_ms, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.ts as i64,
                record.owner,
                record.action,
                record.resource,
                record.duration_ms.map(|d| d as i64),
                meta_to_json(&record.metadata),
            ],
        )?;
        Ok(())
    }

    fn set_counter(&self, key: &str, value: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO counters (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value as i64],
        )?;
        Ok(())
    }

    fn load_snapshot(&self) -> Result<Snapshot> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT * FROM leases")?;
        let leases = stmt
            .query_map([], Self::lease_from_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut stmt = conn.prepare("SELECT * FROM queue ORDER BY seq")?;
        let queue = stmt
            .query_map([], Self::queue_from_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let counter = |key: &str| -> Result<u64> {
            let v: Option<i64> = conn
                .query_row(
                    "SELECT value FROM counters WHERE key = ?1",
                    params![key],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(v.map(|x| x as u64).unwrap_or(1))
        };

        // Derive sane lower bounds from the data itself, in case a counter
        // row was lost but leases survived.
        let max_lease = leases.iter().map(|l| l.id).max().unwrap_or(0) + 1;
        let max_queue = queue.iter().map(|q| q.id).max().unwrap_or(0) + 1;
        let max_seq = queue.iter().map(|q| q.seq).max().unwrap_or(0) + 1;

        let mut stmt = conn.prepare("SELECT key, value FROM counters WHERE key LIKE 'epoch:%'")?;
        let epochs = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|(k, v)| k.strip_prefix("epoch:").map(|r| (r.to_string(), v)))
            .collect();

        Ok(Snapshot {
            leases,
            queue,
            epochs,
            next_lease_id: counter("lease_id")?.max(max_lease),
            next_queue_id: counter("queue_id")?.max(max_queue),
            next_seq: counter("seq")?.max(max_seq),
        })
    }

    fn audit_tail(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT ts, owner, action, resource, duration_ms, metadata
             FROM audit ORDER BY id DESC LIMIT ?1",
        )?;
        let mut rows = stmt
            .query_map(params![limit as i64], |row| {
                let meta_str: String = row.get("metadata")?;
                Ok(AuditRecord {
                    ts: row.get("ts")?,
                    owner: row.get("owner")?,
                    action: row.get("action")?,
                    resource: row.get("resource")?,
                    duration_ms: row.get::<_, Option<i64>>("duration_ms")?.map(|d| d as u64),
                    metadata: meta_from_json(&meta_str),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.reverse();
        Ok(rows)
    }

    fn audit_older_than(&self, cutoff_ms: u64) -> Result<Vec<AuditRecord>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT ts, owner, action, resource, duration_ms, metadata
             FROM audit WHERE ts < ?1 ORDER BY id ASC",
        )?;
        let rows = stmt
            .query_map(params![cutoff_ms as i64], |row| {
                let meta_str: String = row.get("metadata")?;
                Ok(AuditRecord {
                    ts: row.get("ts")?,
                    owner: row.get("owner")?,
                    action: row.get("action")?,
                    resource: row.get("resource")?,
                    duration_ms: row.get::<_, Option<i64>>("duration_ms")?.map(|d| d as u64),
                    metadata: meta_from_json(&meta_str),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn prune_audit_older_than(&self, cutoff_ms: u64) -> Result<u64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let deleted = conn.execute("DELETE FROM audit WHERE ts < ?1", params![cutoff_ms as i64])?;
        Ok(deleted as u64)
    }
}
