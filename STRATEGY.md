# Locksmith — Enterprise Development Strategy

Status: v0.1.3 · Owner: Sal · Reviewed: each release
Companion artifacts: `FRACAS.md` (failure register), `deliver.toml`
(acceptance gate), `.amber.toml` (dependency policy), `kaptaind.toml`
(change control).

## 1. Position

Locksmith is the coordination layer of the multi-agent development stack:
**Git answers what changed, Kaptaind answers why, Locksmith answers who may
change it right now.** The strategy below takes the v0.1 engine to
enterprise grade along five pillars, in dependency order, without breaking
the design tenets (leases over locks, deterministic state, crash
resilience, no distributed database).

## 2. Current state assessment (v0.1.3)

**Strengths**

- Core semantics complete: leases, hierarchy, five queue policies,
  heartbeat expiry, transfer/steal/promote/downgrade, crash recovery —
  38 tests including real SQLite restart recovery.
- Fencing tokens (FM-02/FM-14 closed): persisted per-resource epochs,
  conditional acquire (`if_epoch`, `if_not_held_by`), `X-Locksmith-Epoch`
  response header.
- Monotonic timing (FM-03 closed): expiry and heartbeat timeouts use
  `Instant` anchors re-derived from persisted wall-clock fields on
  recovery.
- Scale and ops: prefix index for descendant checks (FM-11 closed);
  audit retention with JSONL export-before-prune, throttled hourly
  (FM-07 closed).
- Observable: audit log, event bus, Prometheus metrics, JSON API.
- Lean supply chain after amber pass: CLI has 5 direct dependencies
  (reqwest/hyper/rustls removed for a std-based loopback client).
- Hardened: mutex-poison recovery, single-instance `flock` (split-brain
  prevention) — both verified live.
- Change control live: kaptaind auto-commits with a `cargo test
  --workspace` gate; `deliver --strict` gate passes.

**Gaps (drives the phases below)**

- No latency benchmarks, fuzzing, or property tests yet (Phase 2 items
  3 and 5).
- Single transport (loopback TCP), single auth provider (API keys).
- Waiter aging (FM-08) and fleet-id in `/health` (FM-12) outstanding.

## 3. Amber dependency policy (standing)

| Crate | Score | Decision | Rationale |
|---|---|---|---|
| reqwest (CLI) | 64 | **Removed** | Loopback-only traffic; std client suffices. Supply-chain win. |
| serde / tokio | 20 | Keep | Foundational; amber itself classifies as security-critical. |
| rusqlite | 60 | Keep | Persistence core; bundled SQLite, no service dependency. |
| serde_json | 56–58 | Keep | Pervades API/metadata; a hand-rolled JSON layer is a liability. |
| axum | 54 | Keep | HTTP layer; std alternative loses routing/extractor safety. |
| clap | 68–69 | Keep | CLI UX standard; replacement cost > benefit. |
| libc | 62 | Keep | One `signal`/`flock` call each; std exposes neither. |

Policy is encoded in `.amber.toml`; re-run amber each release and record
the diff in this table.

## 4. Phases

### Phase 1 — Foundation hardening ✅ (this tranche)

- [x] Amber analysis + reqwest removal from the CLI
- [x] Mutex-poison recovery; single-instance flock
- [x] FRACAS register; kaptaind monitoring; CI workflow
- [x] `.amber.toml` policy; deliver gate

### Phase 2 — Correctness & scale (in progress)

1. **Fencing tokens** (FM-02/FM-14) ✅ v0.1.3: epoch counter per resource,
   persisted across restarts, returned on every acquire/promotion;
   `X-Locksmith-Epoch` advisory header so downstream writers can reject
   stale holders. Conditional acquire (`if_epoch`, `if_not_held_by`) for
   TOCTOU-safe clients.
2. **Monotonic timing** (FM-03) ✅ v0.1.3: `Instant`-based deadline
   arithmetic internally, re-anchored from persisted wall-clock fields on
   recovery; wall clock only for display/API.
3. **Descendant index** (FM-11): prefix index for hierarchy checks shipped
   v0.1.3; criterion benchmarks asserting acquire p99 < 1 ms at 100k
   leases still pending.
4. **Audit retention** (FM-07) ✅ v0.1.3: `--audit-retain-days` with
   archival export to JSONL before prune, throttled to one pass per hour.
5. **Test depth**: proptest on hierarchy/conflict logic, cargo-fuzz on
   resource-id parsing and the store's row decoders; fleet-id in
   `/health` (FM-12); waiter aging (FM-08).

Exit criteria: zero Open FM rows with RPN ≥ 12 — met at v0.1.3; benches
must meet the directive's latency targets at 100k leases.

### Phase 3 — Enterprise surface

1. Unix-socket transport (default local), gRPC service alongside REST.
2. mTLS and OIDC auth providers behind the existing capability model.
3. Plugin system: scheduler/auth/notification traits with dynamic
   loading, weighted-fair as the reference plugin.
4. LSP extension surfacing ownership in editors.

Exit criteria: auth-provider matrix tested; plugin ABI versioned and
documented; no regression in Phase-2 benchmarks.

### Phase 4 — Availability (bounded)

Cold-standby failover using the existing flock (standby blocks on
`LOCK_EX`, takes over on leader death) + operator runbook. **Explicitly
not** multi-node consensus — the non-goals stand.

## 5. Engineering governance

- **Change control:** kaptaind commits with mandatory test gate; pushes
  stay disabled — humans push.
- **Acceptance gate:** `deliver --strict` must pass before any release
  tag; spec lives in `deliver.toml` and is updated with the feature, not
  after it.
- **Dependency policy:** amber each release; forbidden crates in
  `.amber.toml` fail CI (SARIF job).
- **Failure management:** every incident adds a FRACAS row; Open rows
  with RPN ≥ 12 block minor-version releases.
- **Security:** auth on any non-loopback deployment (skill checklist);
  keys never committed; audit table is append-only and backed up.
- **Performance budget:** uncontended acquire p99 < 1 ms, release <
  0.5 ms, recovery < 2 s at 100k leases — enforced by Phase-2 benches in
  CI (advisory first, blocking once stable).

## 6. KPIs

| KPI | Target | Measured by |
|---|---|---|
| Tests green | 100% | cargo test --workspace |
| Clippy warnings | 0 | CI |
| Direct deps (CLI) | ≤ 6 | amber/cargo tree |
| Acquire p99 (uncontended) | < 1 ms | Phase-2 bench |
| Crash recovery (100k leases) | < 2 s | Phase-2 bench |
| Open FRACAS RPN ≥ 12 | 0 | FRACAS.md |
