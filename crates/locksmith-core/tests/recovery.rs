//! Integration tests against a real SQLite file: write-through persistence
//! and crash recovery.

use std::path::PathBuf;

use locksmith_core::{
    AcquireOutcome, AcquireRequest, Config, LockManager, LockMode, SqliteStore,
};

fn temp_db(name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    let unique = format!(
        "locksmith-test-{}-{}-{}.db",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    );
    dir.push(unique);
    dir
}

#[test]
fn leases_survive_restart() {
    let path = temp_db("restart");
    {
        let store = SqliteStore::open(&path).unwrap();
        let m = LockManager::new(store, Config::default()).unwrap();
        let out = m
            .acquire(AcquireRequest::new(
                "workspace/frontend",
                "hermes",
                LockMode::Exclusive,
            ))
            .unwrap();
        assert!(matches!(out, AcquireOutcome::Granted { .. }));
        // Second owner queues.
        let out = m
            .acquire(AcquireRequest::new(
                "workspace/frontend",
                "openclaw",
                LockMode::Exclusive,
            ))
            .unwrap();
        assert!(matches!(out, AcquireOutcome::Queued { .. }));
    } // manager + store dropped: simulated crash (heartbeats lost)

    {
        let store = SqliteStore::open(&path).unwrap();
        let m = LockManager::new(store, Config::default()).unwrap();
        let view = m.inspect("workspace/frontend");
        assert_eq!(view.leases.len(), 1, "lease must be restored");
        assert_eq!(view.leases[0].owner, "hermes");
        assert_eq!(view.queue.len(), 1, "queue must resume");
        assert_eq!(view.queue[0].owner, "openclaw");
        // Ids must not be reused after restart.
        let out = m
            .acquire(AcquireRequest::new("workspace/backend", "hermes", LockMode::Exclusive))
            .unwrap();
        let AcquireOutcome::Granted { lease } = out else {
            panic!("expected grant");
        };
        assert!(lease.id > 1, "lease ids must continue, got {}", lease.id);
    }

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}

#[test]
fn recovery_expires_stale_leases_and_promotes_queue() {
    let path = temp_db("stale");
    {
        let store = SqliteStore::open(&path).unwrap();
        let config = Config {
            default_lease_ms: 1, // expires almost immediately
            ..Config::default()
        };
        let m = LockManager::new(store, config).unwrap();
        m.acquire(AcquireRequest::new("r", "a", LockMode::Exclusive))
            .unwrap();
        m.acquire(AcquireRequest::new("r", "b", LockMode::Exclusive))
            .unwrap();
    }
    std::thread::sleep(std::time::Duration::from_millis(5));
    {
        let store = SqliteStore::open(&path).unwrap();
        let m = LockManager::new(store, Config::default()).unwrap();
        // Stale lease for 'a' expired on recovery; 'b' was promoted.
        let view = m.inspect("r");
        assert_eq!(view.leases.len(), 1);
        assert_eq!(view.leases[0].owner, "b");
        assert!(view.queue.is_empty());
        let audit = m.audit_tail(20).unwrap();
        assert!(audit.iter().any(|r| r.action == "expire"));
    }

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}

#[test]
fn audit_persists_across_restart() {
    let path = temp_db("audit");
    {
        let store = SqliteStore::open(&path).unwrap();
        let m = LockManager::new(store, Config::default()).unwrap();
        m.acquire(AcquireRequest::new("x", "a", LockMode::Exclusive))
            .unwrap();
        m.release("x", "a").unwrap();
    }
    {
        let store = SqliteStore::open(&path).unwrap();
        let m = LockManager::new(store, Config::default()).unwrap();
        let audit = m.audit_tail(50).unwrap();
        let actions: Vec<&str> = audit.iter().map(|r| r.action.as_str()).collect();
        assert!(actions.contains(&"acquire"));
        assert!(actions.contains(&"release"));
    }
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}
