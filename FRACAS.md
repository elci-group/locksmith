# FRACAS Register — Locksmith

Failure Reporting, Analysis and Corrective Action System register for
Locksmith v0.1. Severity (S) and Likelihood (L) are 1–5; RPN = S × L.
Status: **Mitigated** (control in place and verified), **Accepted**
(residual risk documented), **Open** (corrective action on the roadmap).

Reviewed: every release and after any production incident. New failure
modes are appended with an incrementing FM id — never renumber.

| ID | Component | Failure mode | Cause | Effect | S | L | RPN | Detection | Current mitigation | Corrective action | Status |
|----|-----------|--------------|-------|--------|---|---|-----|-----------|--------------------|-------------------|--------|
| FM-01 | daemon | Process crash mid-operation | panic, OOM, kill -9 | In-memory state lost; holders stop heartbeating | 4 | 2 | 8 | process supervisor, metrics silence | Write-through SQLite; startup replays store, expires stale leases, promotes queues (tested in `recovery.rs`) | — | Mitigated |
| FM-02 | leases | Lease revoked while owner still working | heartbeat timeout under GC pause, network stall, overloaded host | Resource mutated concurrently by promoted owner | 5 | 3 | 15 | `expirations_total` spikes, audit log | 90s default timeout (3 missed beats), 1s sweeper; fencing tokens (v0.1.4): persisted per-resource epoch bumped on every grant/promote/transfer, returned in lease bodies and the `X-Locksmith-Epoch` header so writers reject stale holders | — | Mitigated |
| FM-03 | timing | Wall-clock skew (NTP jump) | clock stepped backwards/forwards | Premature expiry or leases living past deadline | 3 | 2 | 6 | clock monitoring | Monotonic `Instant` anchors for expiry and heartbeat timeouts (v0.1.4); wall clock kept for display/persistence, anchors re-derived on recovery | — | Mitigated |
| FM-04 | manager | Mutex poisoning cascade | panic while holding state lock | Every subsequent operation panics — daemon alive but dead | 4 | 2 | 8 | request error rate | Poison recovered via `into_inner` (v0.1.1); store is source of truth, restart replays | — | Mitigated |
| FM-05 | daemon | Split brain: two daemons, one DB | operator error, container restart race | Divergent in-memory state; conflicting grants | 5 | 2 | 10 | duplicate listeners, audit anomalies | Exclusive `flock` on `<db>.lock` at startup; second daemon refuses to start (verified) | HA failover design: cold standby taking the same lock (Phase 4) | Mitigated |
| FM-06 | store | SQLite corruption / disk full | hardware, filesystem, out-of-space | Store errors surface as HTTP 500; mutations fail | 4 | 2 | 8 | ` Store` errors in logs, scrape failures | WAL mode, `busy_timeout`, backup procedure in skill | Disk-usage alerting; periodic `.backup` automation (Phase 2 ops) | Accepted |
| FM-07 | store | Audit table unbounded growth | append-only by design | DB bloat, slower startup replay | 2 | 4 | 8 | DB size monitoring | Indexed, append-only; retention pass exports records older than `--audit-retain-days` to JSONL, then prunes — throttled to one pass per hour, export failure aborts the prune (v0.1.4) | — | Mitigated |
| FM-08 | scheduler | Queue starvation | `priority` policy + continuous high-priority stream | Low-priority waiters never promoted | 3 | 3 | 9 | `queue_depth` by owner, wait-time metrics | FIFO default; policy documented; `weighted_fair` available | Waiter aging (effective priority rises with wait time) (Phase 2) | Open |
| FM-09 | auth | API key compromise | leaked key file, repo commit | Attacker acts as bound owner | 4 | 2 | 8 | audit anomalies, unknown-owner acquires | Owner binding, capability least-privilege, `steal` restricted, keys never committed (.gitignore + skill checklist) | Key rotation procedure documented; mTLS provider (Phase 3) | Accepted |
| FM-10 | events | Subscriber flood / leak | many SSE-style subscribers (future), dead consumers | Memory growth, emit latency | 2 | 2 | 4 | event buffer metrics | Ring buffer bounded (10k), dead subscribers dropped on send error | — | Mitigated |
| FM-11 | manager | Hierarchy scan latency | descendant conflict check is O(total leases) | Acquire latency degrades with fleet size | 3 | 3 | 9 | latency benchmarks | Prefix index maps ancestors to locked descendants (v0.1.4); conflict checks no longer scan the lease map | Criterion benchmarks to prove the p99 target at 100k leases (Phase 2) | Mitigated |
| FM-12 | CLI | Talking to the wrong daemon | port/env confusion in multi-daemon setups | Leases acquired in the wrong fleet | 3 | 2 | 6 | inspect output surprise | `LOCKSMITH_SERVER` env, clear "cannot reach daemon" hint | Health endpoint reports DB path/fleet id (Phase 2) | Accepted |
| FM-13 | daemon | Stale `<db>.lock` file blocks restart | leftover file after crash | Daemon refuses to start | 3 | 2 | 6 | startup error message | `flock` is held by the process, not the file — kernel releases on death; restart verified non-blocking | — | Mitigated |
| FM-14 | API | TOCTOU between inspect and act | client reads state, acts later | Client acts on stale ownership view | 3 | 4 | 12 | conflicts at acquire time | Acquire is atomic server-side; conditional acquire (v0.1.4): `if_epoch` / `if_not_held_by` preconditions evaluated atomically, 409 on mismatch | — | Mitigated |

## Incident workflow

1. Detect (metrics alert, audit anomaly, user report).
2. Contain: `locksmith inspect <resource>`; if a holder is stuck and the
   capability exists, `locksmith steal <resource> --reason "INC-<id>: …"`.
3. Record: append the incident to this register (new FM row or recurrence
   count on an existing one) and link the audit tail.
4. Correct: promote the corrective action into STRATEGY.md's current phase.
5. Verify: regression test that reproduces the failure mode before the fix.
