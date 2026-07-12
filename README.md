# Locksmith

**Deterministic workspace locking & coordination engine.**

> Git answers *what changed*. Kaptaind answers *why and how it changed*.
> Locksmith answers **who may change it right now**.

Locksmith is not a version control system and not a permissions system. It is a
coordination layer that guarantees deterministic ownership of mutable project
resources — files, directories, GPUs, deployment targets, tasks, agents — so
humans and agents can develop in parallel without silent conflicts.

## Core model

- **Everything is lockable.** A resource is just a string: `file:/src/main.rs`,
  `workspace/frontend`, `gpu:0`, `task:123`, `agent:openclaw`.
- **Leases, not locks.** Every claim has an owner, a lease time (default 20m),
  a heartbeat interval (default 30s) and a heartbeat timeout (default 90s).
- **No permanent locks.** Every lease expires. If heartbeats stop, the lease
  expires and the next queued owner is promoted — no orphan locks, no deadlocks.
- **Explicit ownership.** Every resource always reports owner, since, until,
  queue and metadata.
- **Observable by default.** Every state transition is persisted to SQLite,
  appended to an immutable audit log, and published on an event bus.

## Layout

```
crates/
  locksmith-core/   Lease manager, queue scheduler, heartbeat engine,
                    hierarchy, SQLite persistence, audit log, event bus
  locksmithd/       Coordination daemon: REST API, auth, sweeper, metrics
  locksmith-cli/    `locksmith` command line client
```

## Quick start

```bash
cargo build --release

# 1. Start the daemon (SQLite at ./locksmith.db, API on 127.0.0.1:7700)
./target/release/locksmithd

# 2. Acquire a lease (owner defaults to $USER)
./target/release/locksmith acquire workspace/frontend --lease 20m

# 3. Someone else tries the same resource — they queue
./target/release/locksmith --owner openclaw acquire workspace/frontend

# 4. Inspect ownership
./target/release/locksmith inspect workspace/frontend
```

```
Resource: workspace/frontend
Owner:    sal
Mode:     exclusive
Since:    14:28:58 UTC
Expires:  14:48:58 UTC (in 19m59s)

Queue:
  1. openclaw (exclusive, Normal priority)
```

```bash
# 5. Release — the queue advances automatically
./target/release/locksmith release workspace/frontend
# Released workspace/frontend (sal)
# Promoted: openclaw now holds workspace/frontend (exclusive)
```

## CLI

```
locksmith acquire <resource> [-m exclusive|shared|intent] [-l 20m] [-p high] [--wait]
locksmith release <resource>
locksmith renew <resource>
locksmith heartbeat [resources...]
locksmith inspect <resource>
locksmith queue <resource>
locksmith transfer <resource> --to <owner>
locksmith steal <resource> [--reason ...]
locksmith promote <resource> [-m mode]
locksmith downgrade <resource> [-m mode]
locksmith leases | events | audit | metrics
```

Global flags: `--server` (or `LOCKSMITH_SERVER`), `--owner` (or
`LOCKSMITH_OWNER`, falls back to `$USER`), `--api-key` (or
`LOCKSMITH_API_KEY`), `--json` for machine-readable output.

`acquire --wait` blocks in the queue and returns when the lease is granted
(`--wait-timeout` bounds the wait, default 300s).

## Lock modes and hierarchy

| Held ↓ / Requested → | Shared | Intent | Exclusive |
|---|---|---|---|
| **Shared**    | ok | ok   | conflict |
| **Intent**    | ok | ok   | conflict |
| **Exclusive** | conflict | conflict | conflict |

Resources containing `/` form a tree. Locking `workspace` exclusively blocks
every descendant; a shared lock on `workspace` blocks only exclusive/intent
acquires below it; an exclusive lock on `workspace/frontend/button.rs` blocks
an exclusive lock on `workspace`. The same owner never conflicts with itself
(recursive ownership) and can `promote` (strengthen) or `downgrade` (weaken)
a held lease.

Queue policies (`locksmithd --policy`): `fifo`, `priority`, `shortest-lease`,
`oldest-waiting`, `weighted-fair`.

## REST API

All endpoints take/return JSON. Resource ids travel in bodies or query
strings, never in the path (they contain `/`).

| Method | Path | Body / query |
|---|---|---|
| GET  | `/health` | — |
| POST | `/v1/acquire` | `{resource, owner?, mode?, priority?, lease_ms?, metadata?}` |
| POST | `/v1/release` | `{resource, owner?}` |
| POST | `/v1/renew` | `{resource, owner?}` |
| POST | `/v1/heartbeat` | `{owner?, resources?}` |
| POST | `/v1/transfer` | `{resource, from?, to}` |
| POST | `/v1/steal` | `{resource, owner?, reason?}` |
| POST | `/v1/promote` / `/v1/downgrade` | `{resource, owner?, mode?}` |
| GET  | `/v1/inspect?resource=` | full view incl. ancestor/descendant locks |
| GET  | `/v1/queue?resource=` | waiting queue in policy order |
| GET  | `/v1/leases` | all active leases |
| GET  | `/v1/events?limit=` | event bus tail |
| GET  | `/v1/audit?limit=` | audit log tail |
| GET  | `/v1/metrics` | metrics as JSON |
| GET  | `/metrics` | Prometheus text exposition |

## Authentication

Anonymous access is allowed by default (local development). For shared
daemons, provide an API key file and disable anonymous access:

```bash
locksmithd --api-keys keys.json --no-anonymous
```

```json
{
  "keys": [
    { "key": "secret-hermes", "owner": "hermes" },
    { "key": "secret-admin", "owner": "admin", "capabilities": ["admin"] }
  ]
}
```

A key binds its owner: callers cannot act as another owner unless they hold
`admin`. Capabilities: `acquire`, `release`, `inspect`, `transfer`, `steal`,
`read`, `write`, `admin` (admin bypasses all checks; `steal` is never granted
by default).

## Persistence and crash recovery

State lives in SQLite (default `./locksmith.db`, `--db` / `LOCKSMITH_DB`),
WAL mode, with the directive's tables: `leases`, `owners`, `resources`,
`queue`, `audit`, `sessions` (plus a `counters` table for id sequences).
Every mutation is written through synchronously. On startup the daemon
replays the store, expires leases whose lease time or heartbeat timeout
elapsed while it was down, promotes queued owners, and resumes — recovery
from a crash needs no manual intervention.

## Failure model

```
process crash → heartbeat lost → lease expires → queue advances
```

The sweeper runs every second. A holder that stops heartbeating loses its
leases after the heartbeat timeout (default 90s); an expired lease's queue is
promoted in policy order within one sweep.

## Integration sketch

Git pre-push hook that refuses to push without the deploy lease:

```bash
#!/bin/sh
# .git/hooks/pre-push
locksmith inspect deploy:prod --json | grep -q "\"owner\": \"$USER\"" || {
  echo "push blocked: acquire 'deploy:prod' first (locksmith acquire deploy:prod)"
  exit 1
}
```

Agents (ViCo, OpenOnt, Kaptaind) acquire leases around mutations:

```bash
locksmith acquire task:123 --lease 10m --wait
# ... do the work, heartbeating periodically ...
locksmith heartbeat task:123
locksmith release task:123
```

## Performance notes

The manager keeps authoritative state in memory and writes through to SQLite;
an uncontended acquire is a hash-map check plus one SQLite write (sub-millisecond
locally). Hierarchy checks scan the lease map, so deep wide trees with
hundreds of thousands of simultaneous leases will want a descendant index —
noted as future work. The 1M-lease / 100k-heartbeat-per-second targets from
the directive are design goals for later optimization passes, not benchmarks
this release claims.

## What v0.1 does not include

The directive describes a broad end-state. Deliberately deferred:

- gRPC and Unix-socket transports (REST over loopback TCP today)
- JWT / mTLS / OIDC auth providers (API keys + anonymous today)
- Dynamic plugin system for custom schedulers
- Session-bound and ephemeral lock types (the `sessions` table exists)
- LSP extension for editors

## Development

```bash
cargo test --workspace    # 29 tests: manager semantics, hierarchy, recovery
cargo build --release
```

Core tests cover the conflict matrix, hierarchical locking, queue promotion
under every policy, lease/heartbeat expiry, steal/transfer/promote/downgrade,
and SQLite crash recovery (leases and queues survive restart; stale leases
expire and promote on recovery).
