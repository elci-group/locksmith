//! locksmithd — the Locksmith coordination daemon.
//!
//! Exposes the lease manager over a REST API, runs the heartbeat sweeper,
//! and serves Prometheus metrics.
mod curly_expand;


mod auth;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use serde::Deserialize;

use locksmith_core::{
    AcquireOutcome, AcquireRequest, Config, Error, LockManager, LockMode, Priority, QueuePolicy,
    SqliteStore,
};

use auth::{AuthConfig, Capability, Identity};

/// Locksmith coordination daemon.
#[derive(Parser)]
#[command(name = "locksmithd", version, about)]
struct Args {
    /// SQLite database path.
    #[arg(long, env = "LOCKSMITH_DB", default_value = "locksmith.db")]
    db: PathBuf,

    /// Address to bind the REST API to.
    #[arg(long, env = "LOCKSMITH_BIND", default_value = "127.0.0.1:7700")]
    bind: SocketAddr,

    /// Queue scheduling policy.
    #[arg(long, env = "LOCKSMITH_POLICY", default_value = "fifo")]
    policy: String,

    /// JSON file with API keys (see README for the schema).
    #[arg(long, env = "LOCKSMITH_API_KEYS")]
    api_keys: Option<PathBuf>,

    /// Reject unauthenticated requests.
    #[arg(long, env = "LOCKSMITH_NO_ANONYMOUS")]
    no_anonymous: bool,

    /// Heartbeat sweeper interval in milliseconds.
    #[arg(long, default_value = "1000")]
    sweep_interval_ms: u64,

    /// Default lease duration in seconds.
    #[arg(long, default_value = "1200")]
    default_lease_secs: u64,

    /// Days to retain audit records before archival + pruning (0 = keep forever).
    #[arg(long, env = "LOCKSMITH_AUDIT_RETAIN_DAYS", default_value = "30")]
    audit_retain_days: u64,

    /// JSONL archive receiving audit records before they are pruned
    /// (default: <db>.audit.jsonl when retention is enabled).
    #[arg(long, env = "LOCKSMITH_AUDIT_ARCHIVE")]
    audit_archive: Option<PathBuf>,
}

#[derive(Clone)]
pub struct AppState {
    pub manager: Arc<LockManager<SqliteStore>>,
    pub auth: AuthConfig,
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AcquireBody {
    resource: String,
    owner: Option<String>,
    mode: Option<String>,
    priority: Option<String>,
    lease_ms: Option<u64>,
    heartbeat_interval_ms: Option<u64>,
    heartbeat_timeout_ms: Option<u64>,
    metadata: Option<serde_json::Value>,
    /// Fencing precondition: only proceed if the resource's current epoch
    /// equals this value.
    if_epoch: Option<u64>,
    /// Fencing precondition: only proceed if this owner does not hold the
    /// resource.
    if_not_held_by: Option<String>,
}

#[derive(Deserialize)]
struct ResourceOwnerBody {
    resource: String,
    owner: Option<String>,
}

#[derive(Deserialize)]
struct HeartbeatBody {
    owner: Option<String>,
    resources: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct TransferBody {
    resource: String,
    from: Option<String>,
    to: String,
}

#[derive(Deserialize)]
struct StealBody {
    resource: String,
    owner: Option<String>,
    reason: Option<String>,
}

#[derive(Deserialize)]
struct ModeBody {
    resource: String,
    owner: Option<String>,
    mode: Option<String>,
}

#[derive(Deserialize)]
struct ResourceQuery {
    resource: String,
}

#[derive(Deserialize)]
struct LimitQuery {
    limit: Option<usize>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_mode(s: Option<&str>) -> Result<LockMode, Error> {
    match s {
        None => Ok(LockMode::Exclusive),
        Some(s) => {
            LockMode::parse(s).ok_or_else(|| Error::Invalid(format!("unknown lock mode '{s}'")))
        }
    }
}

fn core_error(err: Error) -> Response {
    let (status, message) = match &err {
        Error::NotHeld { .. } | Error::NotFound(_) => (StatusCode::NOT_FOUND, err.to_string()),
        Error::Conflict { .. } | Error::EpochMismatch { .. } | Error::HeldByOther { .. } => {
            (StatusCode::CONFLICT, err.to_string())
        }
        Error::Invalid(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        Error::PermissionDenied(_) => (StatusCode::FORBIDDEN, err.to_string()),
        Error::Store(_) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

// `Err(Response)` is large but this is an error path; boxing would only
// add an allocation to the happy path's type signature.
type ApiResult = Result<Response, Response>;

#[allow(clippy::result_large_err)]
fn ok(value: impl serde::Serialize) -> ApiResult {
    Ok(Json(value).into_response())
}

/// Respond with a lease, echoing its fencing token in the
/// `X-Locksmith-Epoch` header so downstream writers can reject stale
/// holders (FM-02/FM-14).
#[allow(clippy::result_large_err)]
fn ok_lease(lease: &locksmith_core::Lease) -> ApiResult {
    let mut resp = Json(lease).into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&lease.epoch.to_string()) {
        resp.headers_mut().insert("x-locksmith-epoch", value);
    }
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> Response {
    Json(serde_json::json!({ "status": "ok", "service": "locksmithd" })).into_response()
}

async fn acquire(
    State(state): State<AppState>,
    identity: Identity,
    Json(body): Json<AcquireBody>,
) -> ApiResult {
    identity
        .require(Capability::Acquire)
        .map_err(|(s, j)| (s, j).into_response())?;
    let owner = identity
        .resolve_owner(body.owner.as_deref())
        .map_err(|(s, j)| (s, j).into_response())?;
    let mode = parse_mode(body.mode.as_deref()).map_err(core_error)?;
    let priority = body
        .priority
        .as_deref()
        .and_then(Priority::parse)
        .unwrap_or_default();
    let mut req = AcquireRequest::new(&body.resource, &owner, mode).priority(priority);
    if let Some(ms) = body.lease_ms {
        req = req.lease_ms(ms);
    }
    if let Some(epoch) = body.if_epoch {
        req = req.if_epoch(epoch);
    }
    if let Some(ref blocked) = body.if_not_held_by {
        req = req.if_not_held_by(blocked);
    }
    req.heartbeat_interval_ms = body.heartbeat_interval_ms;
    req.heartbeat_timeout_ms = body.heartbeat_timeout_ms;
    req.metadata = body.metadata.unwrap_or_else(|| serde_json::json!({}));
    let outcome = state.manager.acquire(req).map_err(core_error)?;
    let (status, epoch) = match &outcome {
        AcquireOutcome::Granted { lease } | AcquireOutcome::Held { lease } => {
            (StatusCode::OK, Some(lease.epoch))
        }
        AcquireOutcome::Queued { .. } => (StatusCode::ACCEPTED, None),
    };
    let mut resp = (status, Json(outcome)).into_response();
    if let Some(epoch) = epoch {
        if let Ok(value) = axum::http::HeaderValue::from_str(&epoch.to_string()) {
            resp.headers_mut().insert("x-locksmith-epoch", value);
        }
    }
    Ok(resp)
}

async fn release(
    State(state): State<AppState>,
    identity: Identity,
    Json(body): Json<ResourceOwnerBody>,
) -> ApiResult {
    identity
        .require(Capability::Release)
        .map_err(|(s, j)| (s, j).into_response())?;
    let owner = identity
        .resolve_owner(body.owner.as_deref())
        .map_err(|(s, j)| (s, j).into_response())?;
    let promoted = state
        .manager
        .release(&body.resource, &owner)
        .map_err(core_error)?;
    ok(serde_json::json!({
        "released": true,
        "resource": body.resource,
        "owner": owner,
        "promoted": promoted,
    }))
}

async fn renew(
    State(state): State<AppState>,
    identity: Identity,
    Json(body): Json<ResourceOwnerBody>,
) -> ApiResult {
    identity
        .require(Capability::Acquire)
        .map_err(|(s, j)| (s, j).into_response())?;
    let owner = identity
        .resolve_owner(body.owner.as_deref())
        .map_err(|(s, j)| (s, j).into_response())?;
    let lease = state
        .manager
        .renew(&body.resource, &owner)
        .map_err(core_error)?;
    ok(lease)
}

async fn heartbeat(
    State(state): State<AppState>,
    identity: Identity,
    Json(body): Json<HeartbeatBody>,
) -> ApiResult {
    identity
        .require(Capability::Acquire)
        .map_err(|(s, j)| (s, j).into_response())?;
    let owner = identity
        .resolve_owner(body.owner.as_deref())
        .map_err(|(s, j)| (s, j).into_response())?;
    let count = state
        .manager
        .heartbeat(&owner, body.resources.as_deref())
        .map_err(core_error)?;
    ok(serde_json::json!({ "owner": owner, "leases_refreshed": count }))
}

async fn transfer(
    State(state): State<AppState>,
    identity: Identity,
    Json(body): Json<TransferBody>,
) -> ApiResult {
    identity
        .require(Capability::Transfer)
        .map_err(|(s, j)| (s, j).into_response())?;
    let from = identity
        .resolve_owner(body.from.as_deref())
        .map_err(|(s, j)| (s, j).into_response())?;
    let lease = state
        .manager
        .transfer(&body.resource, &from, &body.to)
        .map_err(core_error)?;
    ok(lease)
}

async fn steal(
    State(state): State<AppState>,
    identity: Identity,
    Json(body): Json<StealBody>,
) -> ApiResult {
    identity
        .require(Capability::Steal)
        .map_err(|(s, j)| (s, j).into_response())?;
    let owner = identity
        .resolve_owner(body.owner.as_deref())
        .map_err(|(s, j)| (s, j).into_response())?;
    let lease = state
        .manager
        .steal(&body.resource, &owner, body.reason.as_deref().unwrap_or(""))
        .map_err(core_error)?;
    ok(lease)
}

async fn promote(
    State(state): State<AppState>,
    identity: Identity,
    Json(body): Json<ModeBody>,
) -> ApiResult {
    identity
        .require(Capability::Acquire)
        .map_err(|(s, j)| (s, j).into_response())?;
    let owner = identity
        .resolve_owner(body.owner.as_deref())
        .map_err(|(s, j)| (s, j).into_response())?;
    let mode = match body.mode.as_deref() {
        Some(s) => Some(parse_mode(Some(s)).map_err(core_error)?),
        None => None,
    };
    let lease = state
        .manager
        .promote(&body.resource, &owner, mode)
        .map_err(core_error)?;
    ok_lease(&lease)
}

async fn downgrade(
    State(state): State<AppState>,
    identity: Identity,
    Json(body): Json<ModeBody>,
) -> ApiResult {
    identity
        .require(Capability::Acquire)
        .map_err(|(s, j)| (s, j).into_response())?;
    let owner = identity
        .resolve_owner(body.owner.as_deref())
        .map_err(|(s, j)| (s, j).into_response())?;
    let mode = match body.mode.as_deref() {
        Some(s) => Some(parse_mode(Some(s)).map_err(core_error)?),
        None => None,
    };
    let promoted = state
        .manager
        .downgrade(&body.resource, &owner, mode)
        .map_err(core_error)?;
    ok(serde_json::json!({ "downgraded": true, "promoted": promoted }))
}

async fn inspect(
    State(state): State<AppState>,
    identity: Identity,
    Query(query): Query<ResourceQuery>,
) -> ApiResult {
    identity
        .require(Capability::Inspect)
        .map_err(|(s, j)| (s, j).into_response())?;
    ok(state.manager.inspect(&query.resource))
}

async fn queue(
    State(state): State<AppState>,
    identity: Identity,
    Query(query): Query<ResourceQuery>,
) -> ApiResult {
    identity
        .require(Capability::Inspect)
        .map_err(|(s, j)| (s, j).into_response())?;
    ok(state.manager.queue(&query.resource))
}

async fn leases(State(state): State<AppState>, identity: Identity) -> ApiResult {
    identity
        .require(Capability::Inspect)
        .map_err(|(s, j)| (s, j).into_response())?;
    ok(state.manager.leases())
}

async fn events(
    State(state): State<AppState>,
    identity: Identity,
    Query(query): Query<LimitQuery>,
) -> ApiResult {
    identity
        .require(Capability::Inspect)
        .map_err(|(s, j)| (s, j).into_response())?;
    ok(state.manager.events(query.limit.unwrap_or(100).min(10_000)))
}

async fn audit(
    State(state): State<AppState>,
    identity: Identity,
    Query(query): Query<LimitQuery>,
) -> ApiResult {
    identity
        .require(Capability::Inspect)
        .map_err(|(s, j)| (s, j).into_response())?;
    let records = state
        .manager
        .audit_tail(query.limit.unwrap_or(100).min(10_000))
        .map_err(core_error)?;
    ok(records)
}

async fn metrics_json(State(state): State<AppState>) -> Response {
    Json(state.manager.metrics()).into_response()
}

async fn metrics(State(state): State<AppState>) -> Response {
    let m = state.manager.metrics();
    let text = format!(
        "# HELP locksmith_acquires_total Acquire requests received.\n\
         # TYPE locksmith_acquires_total counter\n\
         locksmith_acquires_total {acquires}\n\
         # HELP locksmith_grants_total Leases granted immediately.\n\
         # TYPE locksmith_grants_total counter\n\
         locksmith_grants_total {grants}\n\
         # HELP locksmith_queued_total Acquire requests that entered a queue.\n\
         # TYPE locksmith_queued_total counter\n\
         locksmith_queued_total {queued}\n\
         # HELP locksmith_releases_total Leases released.\n\
         # TYPE locksmith_releases_total counter\n\
         locksmith_releases_total {releases}\n\
         # HELP locksmith_renewals_total Lease renewals.\n\
         # TYPE locksmith_renewals_total counter\n\
         locksmith_renewals_total {renewals}\n\
         # HELP locksmith_heartbeats_total Heartbeats processed.\n\
         # TYPE locksmith_heartbeats_total counter\n\
         locksmith_heartbeats_total {heartbeats}\n\
         # HELP locksmith_expirations_total Leases expired (lease time or heartbeat timeout).\n\
         # TYPE locksmith_expirations_total counter\n\
         locksmith_expirations_total {expirations}\n\
         # HELP locksmith_steals_total Lock steals.\n\
         # TYPE locksmith_steals_total counter\n\
         locksmith_steals_total {steals}\n\
         # HELP locksmith_transfers_total Ownership transfers.\n\
         # TYPE locksmith_transfers_total counter\n\
         locksmith_transfers_total {transfers}\n\
         # HELP locksmith_conflicts_total Conflicting acquire attempts.\n\
         # TYPE locksmith_conflicts_total counter\n\
         locksmith_conflicts_total {conflicts}\n\
         # HELP locksmith_queue_promotions_total Queued owners promoted to holders.\n\
         # TYPE locksmith_queue_promotions_total counter\n\
         locksmith_queue_promotions_total {promotions}\n\
         # HELP locksmith_audit_pruned_total Audit records pruned by retention.\n\
         # TYPE locksmith_audit_pruned_total counter\n\
         locksmith_audit_pruned_total {audit_pruned}\n\
         # HELP locksmith_active_leases Currently held leases.\n\
         # TYPE locksmith_active_leases gauge\n\
         locksmith_active_leases {active}\n\
         # HELP locksmith_queue_depth Total queued waiters.\n\
         # TYPE locksmith_queue_depth gauge\n\
         locksmith_queue_depth {depth}\n",
        acquires = m.acquires,
        grants = m.grants,
        queued = m.queued,
        releases = m.releases,
        renewals = m.renewals,
        heartbeats = m.heartbeats,
        expirations = m.expirations,
        steals = m.steals,
        transfers = m.transfers,
        conflicts = m.conflicts,
        promotions = m.queue_promotions,
        audit_pruned = m.audit_pruned,
        active = m.active_leases,
        depth = m.queue_depth,
    );
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        text,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Single-instance lock
// ---------------------------------------------------------------------------

/// Exclusive advisory lock preventing two daemons from sharing one database.
/// Two daemons on one DB would diverge in memory (split brain) — SQLite's
/// own locking only serializes individual writes, not manager state. The
/// lock is held for the process lifetime and released by the OS on exit.
struct DaemonLock {
    _file: std::fs::File,
}

impl DaemonLock {
    #[cfg(unix)]
    fn acquire(db_path: &std::path::Path) -> Result<Self, String> {
        use std::io::Write;
        use std::os::unix::io::AsRawFd;

        let lock_path = match db_path.file_name() {
            Some(name) => db_path.with_file_name(format!("{}.lock", name.to_string_lossy())),
            None => db_path.with_extension("lock"),
        };
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false) // truncated via set_len only after the flock is held
            .open(&lock_path)
            .map_err(|e| format!("cannot open lock file {}: {e}", lock_path.display()))?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let owner = std::fs::read_to_string(&lock_path).unwrap_or_default();
            return Err(format!(
                "another locksmithd holds {} (pid: {}). Stop it or pass a different --db.",
                lock_path.display(),
                owner.trim()
            ));
        }
        file.set_len(0).map_err(|e| e.to_string())?;
        let mut f = &file;
        writeln!(f, "{}", std::process::id()).map_err(|e| e.to_string())?;
        Ok(DaemonLock { _file: file })
    }

    #[cfg(not(unix))]
    fn acquire(_db_path: &std::path::Path) -> Result<Self, String> {
        Err("single-instance locking is only supported on unix".to_string())
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn __curly_original_main() {
    let args = Args::parse();

    let policy = match QueuePolicy::parse(&args.policy) {
        Some(p) => p,
        None => {
            eprintln!(
                "unknown queue policy '{}'; expected fifo, priority, shortest-lease, oldest-waiting or weighted-fair",
                args.policy
            );
            std::process::exit(2);
        }
    };

    let auth = match AuthConfig::load(args.api_keys.as_deref(), !args.no_anonymous) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    if let Some(parent) = args.db.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("cannot create database directory {}: {e}", parent.display());
                std::process::exit(1);
            }
        }
    }

    let _daemon_lock = match DaemonLock::acquire(&args.db) {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let store = match SqliteStore::open(&args.db) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot open database {}: {e}", args.db.display());
            std::process::exit(1);
        }
    };

    let audit_archive_path = args.audit_archive.clone().or_else(|| {
        if args.audit_retain_days > 0 {
            let mut p = args.db.clone().into_os_string();
            p.push(".audit.jsonl");
            Some(PathBuf::from(p))
        } else {
            None
        }
    });
    let config = Config {
        default_lease_ms: args.default_lease_secs * 1000,
        queue_policy: policy,
        audit_retention_days: args.audit_retain_days,
        audit_archive_path,
        ..Config::default()
    };

    let manager = match LockManager::new(store, config) {
        Ok(m) => Arc::new(m),
        Err(e) => {
            eprintln!("failed to start lease manager: {e}");
            std::process::exit(1);
        }
    };

    // Heartbeat sweeper: expire dead leases, advance queues.
    let sweeper = manager.clone();
    let interval_ms = args.sweep_interval_ms;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(interval_ms));
        loop {
            interval.tick().await;
            if let Err(e) = sweeper.sweep() {
                eprintln!("sweep error: {e}");
            }
        }
    });

    let state = AppState { manager, auth };

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/acquire", post(acquire))
        .route("/v1/release", post(release))
        .route("/v1/renew", post(renew))
        .route("/v1/heartbeat", post(heartbeat))
        .route("/v1/transfer", post(transfer))
        .route("/v1/steal", post(steal))
        .route("/v1/promote", post(promote))
        .route("/v1/downgrade", post(downgrade))
        .route("/v1/inspect", get(inspect))
        .route("/v1/queue", get(queue))
        .route("/v1/leases", get(leases))
        .route("/v1/events", get(events))
        .route("/v1/audit", get(audit))
        .route("/v1/metrics", get(metrics_json))
        .route("/metrics", get(metrics))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(args.bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind {}: {e}", args.bind);
            std::process::exit(1);
        }
    };

    eprintln!(
        "locksmithd {} listening on http://{} (db: {}, policy: {})",
        env!("CARGO_PKG_VERSION"),
        args.bind,
        args.db.display(),
        args.policy,
    );

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}

fn main() {
    let raw_args: Vec<String> = std::env::args().collect();
    let mut positions: Vec<usize> = Vec::new();
    let mut fields: Vec<Vec<String>> = Vec::new();
    for (__i, __a) in raw_args.iter().enumerate() {
        if __a == "--db" {
            if let Some(__v) = raw_args.get(__i + 1) {
                positions.push(__i + 1);
                fields.push(curly_expand::expand_or_literal(__v));
            }
            break;
        } else if let Some(__v) = __a.strip_prefix("--db=") {
            positions.push(__i);
            fields.push(
                curly_expand::expand_or_literal(__v)
                    .into_iter()
                    .map(|v| format!("--db={}", v))
                    .collect(),
            );
            break;
        }
    }
    for (__i, __a) in raw_args.iter().enumerate() {
        if __a == "--policy" {
            if let Some(__v) = raw_args.get(__i + 1) {
                positions.push(__i + 1);
                fields.push(curly_expand::expand_or_literal(__v));
            }
            break;
        } else if let Some(__v) = __a.strip_prefix("--policy=") {
            positions.push(__i);
            fields.push(
                curly_expand::expand_or_literal(__v)
                    .into_iter()
                    .map(|v| format!("--policy={}", v))
                    .collect(),
            );
            break;
        }
    }
    for (__i, __a) in raw_args.iter().enumerate() {
        if __a == "--api-keys" {
            if let Some(__v) = raw_args.get(__i + 1) {
                positions.push(__i + 1);
                fields.push(curly_expand::expand_or_literal(__v));
            }
            break;
        } else if let Some(__v) = __a.strip_prefix("--api-keys=") {
            positions.push(__i);
            fields.push(
                curly_expand::expand_or_literal(__v)
                    .into_iter()
                    .map(|v| format!("--api-keys={}", v))
                    .collect(),
            );
            break;
        }
    }
    for (__i, __a) in raw_args.iter().enumerate() {
        if __a == "--audit-archive" {
            if let Some(__v) = raw_args.get(__i + 1) {
                positions.push(__i + 1);
                fields.push(curly_expand::expand_or_literal(__v));
            }
            break;
        } else if let Some(__v) = __a.strip_prefix("--audit-archive=") {
            positions.push(__i);
            fields.push(
                curly_expand::expand_or_literal(__v)
                    .into_iter()
                    .map(|v| format!("--audit-archive={}", v))
                    .collect(),
            );
            break;
        }
    }

    if fields.is_empty() || fields.iter().all(|f| f.len() <= 1) {
        __curly_original_main();
        return;
    }

    let combos = curly_expand::cartesian(&fields);
    let exe = std::env::current_exe().expect("resolve current exe");
    let mut had_failure = false;
    for combo in &combos {
        let mut new_args = raw_args.clone();
        for (slot, value) in positions.iter().zip(combo.iter()) {
            new_args[*slot] = value.clone();
        }
        let status = std::process::Command::new(&exe)
            .args(&new_args[1..])
            .status()
            .expect("failed to re-exec self");
        if !status.success() {
            had_failure = true;
        }
    }
    if had_failure {
        std::process::exit(1);
    }
}
