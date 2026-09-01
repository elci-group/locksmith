//! locksmith — command line client for the Locksmith coordination daemon.

mod http;
mod theme;

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde::Deserialize;

use locksmith_core::{
    AcquireOutcome, AuditRecord, Event, Lease, LockMode, MetricsSnapshot, Priority, QueueEntry,
    ResourceView, SoftwareProvider,
};
use theme::{RenderMode, Status, Theme, Variant};

/// Locksmith CLI: workspace locking and coordination.
#[derive(Parser)]
#[command(name = "locksmith", version, about)]
struct Cli {
    /// Daemon base URL.
    #[arg(
        long,
        env = "LOCKSMITH_SERVER",
        default_value = "http://127.0.0.1:7700",
        global = true
    )]
    server: String,

    /// API key for authenticated daemons.
    #[arg(long, env = "LOCKSMITH_API_KEY", global = true)]
    api_key: Option<String>,

    /// Owner identity for lease operations.
    #[arg(long, env = "LOCKSMITH_OWNER", global = true)]
    owner: Option<String>,

    /// Emit raw JSON.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Acquire a lease on a resource.
    Acquire {
        resource: String,
        /// Lock mode: exclusive, shared or intent.
        #[arg(long, short, default_value = "exclusive")]
        mode: String,
        /// Lease duration, e.g. 20m, 90s, 1h.
        #[arg(long, short)]
        lease: Option<String>,
        /// Queue priority: low, normal, high, critical.
        #[arg(long, short, default_value = "normal")]
        priority: String,
        /// Wait in the queue until the lease is granted.
        #[arg(long, short)]
        wait: bool,
        /// Give up waiting after this many seconds.
        #[arg(long, default_value = "300")]
        wait_timeout: u64,
        /// Fencing precondition: fail unless the resource's current epoch
        /// equals this value (see `locksmith inspect`).
        #[arg(long)]
        if_epoch: Option<u64>,
        /// Fencing precondition: fail if this owner currently holds the
        /// resource.
        #[arg(long)]
        if_not_held_by: Option<String>,
        /// Attach JSON metadata to the lease.
        #[arg(long)]
        metadata: Option<String>,
    },
    /// Release a lease.
    Release { resource: String },
    /// Renew a lease (extend its expiry).
    Renew { resource: String },
    /// Heartbeat your leases to keep them alive.
    Heartbeat {
        /// Restrict to these resources (default: all leases of the owner).
        resources: Vec<String>,
    },
    /// Inspect a resource: owner, expiry, queue.
    Inspect { resource: String },
    /// Show the waiting queue of a resource.
    Queue { resource: String },
    /// Transfer ownership without releasing.
    Transfer {
        resource: String,
        /// New owner.
        #[arg(long)]
        to: String,
    },
    /// Forcibly take a resource from its current holder.
    Steal {
        resource: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Promote a held lease (shared -> exclusive by default).
    Promote {
        resource: String,
        #[arg(long, short)]
        mode: Option<String>,
    },
    /// Downgrade a held lease (exclusive -> shared by default).
    Downgrade {
        resource: String,
        #[arg(long, short)]
        mode: Option<String>,
    },
    /// List all active leases.
    Leases,
    /// Show recent events.
    Events {
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Show the audit log tail.
    Audit {
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Show daemon metrics.
    Metrics,
    /// Manage sealed secrets at rest. Local file operations — no running
    /// daemon required.
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
}

#[derive(Subcommand)]
enum TrustCommand {
    /// Seal a plaintext API keys JSON file for `locksmithd --api-keys-sealed`.
    SealKeys {
        /// Plaintext api keys JSON file (see README `## Authentication`).
        #[arg(long)]
        input: PathBuf,
        /// Path to write the sealed file to.
        #[arg(long)]
        output: PathBuf,
        /// Software trust key file, generated if it doesn't exist yet.
        #[arg(long, env = "LOCKSMITH_TRUST_KEY")]
        trust_key: PathBuf,
    },
    /// Unseal a sealed API keys file back to plaintext (inspection/migration).
    UnsealKeys {
        /// Sealed input file.
        #[arg(long)]
        input: PathBuf,
        /// Where to write the plaintext (default: stdout).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Software trust key file that sealed the input.
        #[arg(long, env = "LOCKSMITH_TRUST_KEY")]
        trust_key: PathBuf,
    },
    /// Report the trust backend in use on this machine.
    Status,
}

struct Ctx {
    client: http::Client,
    server: String,
    owner: String,
    owner_explicit: bool,
    api_key: Option<String>,
    json: bool,
    theme: Theme,
}

impl Ctx {
    /// The owner to send in request bodies. When the user did not pass
    /// `--owner` explicitly and an API key is in use, we omit it so the
    /// daemon binds the owner from the authenticated identity.
    fn request_owner(&self) -> Option<&str> {
        if self.owner_explicit || self.api_key.is_none() {
            Some(&self.owner)
        } else {
            None
        }
    }

    /// Shared response handling: map transport errors to a friendly hint,
    /// extract daemon error messages, decode the body.
    fn decode<R: serde::de::DeserializeOwned>(
        &self,
        result: Result<(u16, String), String>,
    ) -> Result<R, String> {
        let (status, text) = result.map_err(|e| {
            format!(
                "cannot reach daemon at {}: {e}\n  is locksmithd running?",
                self.server
            )
        })?;
        if !(200..300).contains(&status) {
            let msg = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
                .unwrap_or(text);
            return Err(format!("{msg} (HTTP {status})"));
        }
        serde_json::from_str(&text).map_err(|e| format!("invalid response: {e}: {text}"))
    }

    fn post<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, String> {
        let text = serde_json::to_string(body).map_err(|e| e.to_string())?;
        self.decode(self.client.post_json(path, &text, self.api_key.as_deref()))
    }

    fn get<R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<R, String> {
        self.decode(self.client.get(path, query, self.api_key.as_deref()))
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers (timestamps are UTC; no timezone database required)
// ---------------------------------------------------------------------------

fn fmt_hms(ms: u64) -> String {
    let secs = ms / 1000;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn fmt_relative(target_ms: u64) -> String {
    let now = now_ms() as i64;
    let delta = target_ms as i64 - now;
    let (label, abs) = if delta >= 0 {
        ("in", delta)
    } else {
        ("", -delta)
    };
    let secs = abs / 1000;
    let body = if secs >= 3600 {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    };
    if delta >= 0 {
        format!("{label} {body}")
    } else {
        format!("expired {body} ago")
    }
}

fn parse_duration_ms(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1_000)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3_600_000)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86_400_000)
    } else {
        (s, 1_000) // bare number = seconds
    };
    num.trim()
        .parse::<u64>()
        .map(|v| v * mult)
        .map_err(|_| format!("invalid duration '{s}' (try 30s, 20m, 1h)"))
}

fn print_lease(theme: &Theme, lease: &Lease) {
    let icon = theme.owned_icon(Status::Held(lease.mode), &lease.owner, Variant::Holding);
    let owner = theme.owner(&lease.owner, Variant::Holding);
    println!("{icon} Owner:    {owner}");
    println!("  Mode:     {}", lease.mode.as_str());
    println!("  Token:    {}", lease.epoch);
    println!("  Since:    {} UTC", fmt_hms(lease.acquired_at));
    println!(
        "  Expires:  {} UTC ({})",
        fmt_hms(lease.expires_at),
        fmt_relative(lease.expires_at)
    );
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn cmd_acquire(
    ctx: &Ctx,
    resource: &str,
    mode: &str,
    lease: Option<&str>,
    priority: &str,
    wait: bool,
    wait_timeout: u64,
    metadata: Option<&str>,
    if_epoch: Option<u64>,
    if_not_held_by: Option<&str>,
) -> Result<(), String> {
    if LockMode::parse(mode).is_none() {
        return Err(format!("unknown mode '{mode}' (exclusive|shared|intent)"));
    }
    if Priority::parse(priority).is_none() {
        return Err(format!(
            "unknown priority '{priority}' (low|normal|high|critical)"
        ));
    }
    let lease_ms = match lease {
        Some(l) => Some(parse_duration_ms(l)?),
        None => None,
    };
    let meta = match metadata {
        Some(m) => serde_json::from_str::<serde_json::Value>(m)
            .map_err(|e| format!("invalid metadata JSON: {e}"))?,
        None => serde_json::json!({}),
    };

    let body = serde_json::json!({
        "resource": resource,
        "owner": ctx.request_owner(),
        "mode": mode,
        "priority": priority,
        "lease_ms": lease_ms,
        "metadata": meta,
        "if_epoch": if_epoch,
        "if_not_held_by": if_not_held_by,
    });

    let started = std::time::Instant::now();
    let timeout = Duration::from_secs(wait_timeout);
    let mut last_position: Option<usize> = None;
    let mut spinner = ctx.theme.spinner();
    let animate = ctx.theme.animate() && wait;
    loop {
        let outcome: AcquireOutcome = ctx.post("/v1/acquire", &body)?;
        match outcome {
            AcquireOutcome::Granted { lease } => {
                if animate {
                    eprint!("\r\x1b[2K");
                }
                if ctx.json {
                    println!("{}", serde_json::to_string_pretty(&lease).unwrap());
                } else {
                    let icon = ctx.theme.status_icon(Status::Held(lease.mode));
                    println!("{icon} Acquired {resource}");
                    print_lease(&ctx.theme, &lease);
                }
                return Ok(());
            }
            AcquireOutcome::Held { lease } => {
                if ctx.json {
                    println!("{}", serde_json::to_string_pretty(&lease).unwrap());
                } else {
                    let icon = ctx.theme.status_icon(Status::Held(lease.mode));
                    println!("{icon} Already held {resource}");
                    print_lease(&ctx.theme, &lease);
                }
                return Ok(());
            }
            AcquireOutcome::Queued { entry, position } => {
                if !wait {
                    if ctx.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "status": "queued",
                                "position": position,
                                "entry": entry,
                            }))
                            .unwrap()
                        );
                    } else {
                        let icon = ctx.theme.icon(Status::Queued);
                        println!("{icon} Queued for {resource} at position {position}");
                        println!("  Held by:  {}", holding_summary(ctx, resource));
                        println!(
                            "  Mode:     {} ({})",
                            entry.mode.as_str(),
                            ctx.theme.owner(&ctx.owner, Variant::Attempting)
                        );
                        println!(
                            "  {}",
                            ctx.theme
                                .dim("Hint:     re-run with --wait to block until granted")
                        );
                    }
                    return Ok(());
                }
                if animate {
                    let frame = spinner.tick();
                    let owner = ctx.theme.owner(&ctx.owner, Variant::Attempting);
                    eprint!(
                        "\r\x1b[2K{frame} waiting for {resource}: position {position} ({owner})"
                    );
                    use std::io::Write;
                    let _ = std::io::stderr().flush();
                } else if last_position != Some(position) {
                    let icon = ctx.theme.icon(Status::Queued);
                    eprintln!("{icon} waiting for {resource}: queue position {position}");
                    last_position = Some(position);
                }
                if started.elapsed() > timeout {
                    if animate {
                        eprintln!();
                    }
                    return Err(format!(
                        "timed out after {wait_timeout}s waiting for '{resource}' (position {position})"
                    ));
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

fn holding_summary(ctx: &Ctx, resource: &str) -> String {
    let view: Result<ResourceView, _> = ctx.get("/v1/inspect", &[("resource", resource)]);
    match view {
        Ok(v) if !v.leases.is_empty() => v
            .leases
            .iter()
            .map(|l| {
                format!(
                    "{} {} ({})",
                    ctx.theme
                        .owned_icon(Status::Held(l.mode), &l.owner, Variant::Holding),
                    ctx.theme.owner(&l.owner, Variant::Holding),
                    l.mode.as_str()
                )
            })
            .collect::<Vec<_>>()
            .join(", "),
        _ => "unknown".to_string(),
    }
}

fn cmd_release(ctx: &Ctx, resource: &str) -> Result<(), String> {
    #[derive(Deserialize)]
    struct ReleaseResponse {
        promoted: Vec<Lease>,
    }
    let resp: ReleaseResponse = ctx.post(
        "/v1/release",
        &serde_json::json!({ "resource": resource, "owner": ctx.request_owner() }),
    )?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&resp.promoted).unwrap());
    } else {
        let icon = ctx.theme.status_icon(Status::Free);
        println!(
            "{icon} Released {resource} ({})",
            ctx.theme.owner(&ctx.owner, Variant::Holding)
        );
        for lease in &resp.promoted {
            let up = ctx
                .theme
                .owned_icon(Status::Promoted, &lease.owner, Variant::Holding);
            println!(
                "  {up} Promoted: {} now holds {} ({})",
                ctx.theme.owner(&lease.owner, Variant::Holding),
                lease.resource,
                lease.mode.as_str()
            );
        }
    }
    Ok(())
}

fn cmd_renew(ctx: &Ctx, resource: &str) -> Result<(), String> {
    let lease: Lease = ctx.post(
        "/v1/renew",
        &serde_json::json!({ "resource": resource, "owner": ctx.request_owner() }),
    )?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&lease).unwrap());
    } else {
        let icon = ctx.theme.status_icon(Status::Held(lease.mode));
        println!("{icon} Renewed {resource}");
        print_lease(&ctx.theme, &lease);
    }
    Ok(())
}

fn cmd_heartbeat(ctx: &Ctx, resources: &[String]) -> Result<(), String> {
    #[derive(Deserialize, serde::Serialize)]
    struct HeartbeatResponse {
        leases_refreshed: usize,
    }
    let body = serde_json::json!({
        "owner": ctx.request_owner(),
        "resources": if resources.is_empty() { None } else { Some(resources) },
    });
    let resp: HeartbeatResponse = ctx.post("/v1/heartbeat", &body)?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
    } else {
        let icon = ctx.theme.status_icon(Status::Heartbeat);
        println!(
            "{icon} Heartbeat: {} lease(s) refreshed for {}",
            resp.leases_refreshed,
            ctx.theme.owner(&ctx.owner, Variant::Holding)
        );
    }
    Ok(())
}

fn cmd_inspect(ctx: &Ctx, resource: &str) -> Result<(), String> {
    let view: ResourceView = ctx.get("/v1/inspect", &[("resource", resource)])?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&view).unwrap());
        return Ok(());
    }
    let head_icon = if view.leases.is_empty() {
        ctx.theme.status_icon(Status::Free)
    } else {
        ctx.theme.status_icon(Status::Held(view.leases[0].mode))
    };
    println!("{head_icon} Resource: {resource}");
    println!("  Epoch:    {}", view.epoch);
    if view.leases.is_empty() {
        println!("  Owner:    (none — unlocked)");
    } else {
        for lease in &view.leases {
            print_lease(&ctx.theme, lease);
            println!();
        }
    }
    if !view.queue.is_empty() {
        println!("Queue:");
        for (i, entry) in view.queue.iter().enumerate() {
            let icon = ctx
                .theme
                .owned_icon(Status::Queued, &entry.owner, Variant::Attempting);
            println!(
                "  {}. {icon} {} ({}, {:?} priority)",
                i + 1,
                ctx.theme.owner(&entry.owner, Variant::Attempting),
                entry.mode.as_str(),
                entry.priority
            );
        }
    }
    if !view.ancestor_locks.is_empty() {
        println!("Ancestor locks:");
        for lease in &view.ancestor_locks {
            let icon =
                ctx.theme
                    .owned_icon(Status::Held(lease.mode), &lease.owner, Variant::Holding);
            println!(
                "  {icon} {} held by {} ({})",
                lease.resource,
                ctx.theme.owner(&lease.owner, Variant::Holding),
                lease.mode.as_str()
            );
        }
    }
    if !view.descendant_locks.is_empty() {
        println!("Descendant locks:");
        for lease in &view.descendant_locks {
            let icon =
                ctx.theme
                    .owned_icon(Status::Held(lease.mode), &lease.owner, Variant::Holding);
            println!(
                "  {icon} {} held by {} ({})",
                lease.resource,
                ctx.theme.owner(&lease.owner, Variant::Holding),
                lease.mode.as_str()
            );
        }
    }
    Ok(())
}

fn cmd_queue(ctx: &Ctx, resource: &str) -> Result<(), String> {
    let queue: Vec<QueueEntry> = ctx.get("/v1/queue", &[("resource", resource)])?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&queue).unwrap());
        return Ok(());
    }
    if queue.is_empty() {
        let icon = ctx.theme.status_icon(Status::Free);
        println!("{icon} Queue for {resource} is empty");
    } else {
        let icon = ctx.theme.icon(Status::Queued);
        println!("{icon} Queue for {resource}:");
        for (i, entry) in queue.iter().enumerate() {
            let entry_icon =
                ctx.theme
                    .owned_icon(Status::Queued, &entry.owner, Variant::Attempting);
            println!(
                "  {}. {entry_icon} {} ({}, {:?} priority, waiting since {} UTC)",
                i + 1,
                ctx.theme.owner(&entry.owner, Variant::Attempting),
                entry.mode.as_str(),
                entry.priority,
                fmt_hms(entry.requested_at)
            );
        }
    }
    Ok(())
}

fn cmd_transfer(ctx: &Ctx, resource: &str, to: &str) -> Result<(), String> {
    let lease: Lease = ctx.post(
        "/v1/transfer",
        &serde_json::json!({ "resource": resource, "from": ctx.request_owner(), "to": to }),
    )?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&lease).unwrap());
    } else {
        let icon = ctx.theme.status_icon(Status::Held(lease.mode));
        println!(
            "{icon} {} {resource}: {} -> {}",
            ctx.theme.good("Transferred"),
            ctx.theme.owner(&ctx.owner, Variant::Attempting),
            ctx.theme.owner(to, Variant::Holding)
        );
    }
    Ok(())
}

fn cmd_steal(ctx: &Ctx, resource: &str, reason: Option<&str>) -> Result<(), String> {
    let lease: Lease = ctx.post(
        "/v1/steal",
        &serde_json::json!({
            "resource": resource,
            "owner": ctx.request_owner(),
            "reason": reason.unwrap_or(""),
        }),
    )?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&lease).unwrap());
    } else {
        let icon = ctx.theme.status_icon(Status::Stolen);
        println!("{icon} Stole {resource}");
        print_lease(&ctx.theme, &lease);
    }
    Ok(())
}

fn cmd_promote(ctx: &Ctx, resource: &str, mode: Option<&str>) -> Result<(), String> {
    let lease: Lease = ctx.post(
        "/v1/promote",
        &serde_json::json!({ "resource": resource, "owner": ctx.request_owner(), "mode": mode }),
    )?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&lease).unwrap());
    } else {
        let icon = ctx
            .theme
            .owned_icon(Status::Promoted, &lease.owner, Variant::Holding);
        println!("{icon} Promoted {resource} to {}", lease.mode.as_str());
    }
    Ok(())
}

fn cmd_downgrade(ctx: &Ctx, resource: &str, mode: Option<&str>) -> Result<(), String> {
    let resp: serde_json::Value = ctx.post(
        "/v1/downgrade",
        &serde_json::json!({ "resource": resource, "owner": ctx.request_owner(), "mode": mode }),
    )?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
    } else {
        let icon = ctx
            .theme
            .owned_icon(Status::Downgraded, &ctx.owner, Variant::Holding);
        println!("{icon} Downgraded {resource}");
    }
    Ok(())
}

fn cmd_leases(ctx: &Ctx) -> Result<(), String> {
    let leases: Vec<Lease> = ctx.get("/v1/leases", &[])?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&leases).unwrap());
        return Ok(());
    }
    if leases.is_empty() {
        println!("{} No active leases", ctx.theme.status_icon(Status::Free));
    } else {
        println!(
            "   {:<40} {:<20} {:<10} EXPIRES",
            "RESOURCE", "OWNER", "MODE"
        );
        for lease in &leases {
            let icon =
                ctx.theme
                    .owned_icon(Status::Held(lease.mode), &lease.owner, Variant::Holding);
            let owner = ctx.theme.owner(&lease.owner, Variant::Holding);
            println!(
                "{icon} {:<40} {:<20} {:<10} {} ({})",
                lease.resource,
                owner,
                lease.mode.as_str(),
                fmt_hms(lease.expires_at),
                fmt_relative(lease.expires_at),
            );
        }
    }
    Ok(())
}

fn cmd_events(ctx: &Ctx, limit: usize) -> Result<(), String> {
    let events: Vec<Event> = ctx.get("/v1/events", &[("limit", &limit.to_string())])?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&events).unwrap());
        return Ok(());
    }
    for event in &events {
        let owner = ctx.theme.owner(&event.owner, Variant::Holding);
        println!(
            "#{:>5} {}  {:?}  {}  {}",
            event.seq,
            fmt_hms(event.ts),
            event.kind,
            event.resource,
            owner
        );
    }
    Ok(())
}

fn cmd_audit(ctx: &Ctx, limit: usize) -> Result<(), String> {
    let records: Vec<AuditRecord> = ctx.get("/v1/audit", &[("limit", &limit.to_string())])?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&records).unwrap());
        return Ok(());
    }
    for record in &records {
        let duration = record
            .duration_ms
            .map(|d| format!(" ({}ms)", d))
            .unwrap_or_default();
        let owner = ctx.theme.owner(&record.owner, Variant::Holding);
        println!(
            "{}  {:<10} {:<20} {}{}",
            fmt_hms(record.ts),
            record.action,
            owner,
            record.resource,
            duration
        );
    }
    Ok(())
}

fn cmd_metrics(ctx: &Ctx) -> Result<(), String> {
    let snapshot: MetricsSnapshot = ctx.get("/v1/metrics", &[])?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&snapshot).unwrap());
        return Ok(());
    }
    let lock_icon = if snapshot.active_leases > 0 {
        ctx.theme.icon(Status::Held(LockMode::Exclusive))
    } else {
        ctx.theme.icon(Status::Free)
    };
    println!("{lock_icon} Active leases:    {}", snapshot.active_leases);
    println!("Queue depth:      {}", snapshot.queue_depth);
    println!("Acquires:         {}", snapshot.acquires);
    println!("Grants:           {}", snapshot.grants);
    println!("Queued:           {}", snapshot.queued);
    println!("Releases:         {}", snapshot.releases);
    println!("Renewals:         {}", snapshot.renewals);
    println!("Heartbeats:       {}", snapshot.heartbeats);
    println!("Expirations:      {}", snapshot.expirations);
    println!("Steals:           {}", snapshot.steals);
    println!("Transfers:        {}", snapshot.transfers);
    println!("Conflicts:        {}", snapshot.conflicts);
    println!("Queue promotions: {}", snapshot.queue_promotions);
    println!("Audit pruned:     {}", snapshot.audit_pruned);
    Ok(())
}

// ---------------------------------------------------------------------------
// Trust: local sealing of secrets at rest (no daemon required)
// ---------------------------------------------------------------------------

fn run_trust_command(theme: &Theme, command: TrustCommand) -> Result<(), String> {
    match command {
        TrustCommand::SealKeys {
            input,
            output,
            trust_key,
        } => {
            let plaintext = std::fs::read(&input)
                .map_err(|e| format!("cannot read {}: {e}", input.display()))?;
            // Validate it parses as an api keys file before sealing garbage.
            serde_json::from_slice::<serde_json::Value>(&plaintext)
                .map_err(|e| format!("{} is not valid JSON: {e}", input.display()))?;
            let provider = SoftwareProvider::open_or_create(&trust_key)
                .map_err(|e| format!("cannot open trust key {}: {e}", trust_key.display()))?;
            locksmith_core::seal_to_file(&provider, &plaintext, &output)
                .map_err(|e| format!("cannot write sealed file {}: {e}", output.display()))?;
            let icon = theme.status_icon(Status::Sealed);
            println!(
                "{icon} sealed {} -> {} (trust key: {})",
                input.display(),
                output.display(),
                trust_key.display()
            );
            Ok(())
        }
        TrustCommand::UnsealKeys {
            input,
            output,
            trust_key,
        } => {
            let provider = SoftwareProvider::open_or_create(&trust_key)
                .map_err(|e| format!("cannot open trust key {}: {e}", trust_key.display()))?;
            let plaintext = locksmith_core::unseal_from_file(&provider, &input)
                .map_err(|e| format!("cannot unseal {}: {e}", input.display()))?;
            match output {
                Some(path) => {
                    std::fs::write(&path, &plaintext)
                        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
                    let icon = theme.status_icon(Status::Unsealed);
                    println!("{icon} unsealed {} -> {}", input.display(), path.display());
                }
                None => {
                    use std::io::Write;
                    std::io::stdout()
                        .write_all(&plaintext)
                        .map_err(|e| e.to_string())?;
                }
            }
            Ok(())
        }
        TrustCommand::Status => {
            let tpm = locksmith_core::tpm2_present();
            let icon = theme.icon(Status::Sealed);
            println!("{icon} security_mode: software");
            println!("  hardware_backed: false");
            println!(
                "  tpm2_device: {}",
                if tpm {
                    "present (unused: no hardware backend yet)"
                } else {
                    "not detected"
                }
            );
            Ok(())
        }
    }
}

fn main() {
    // Restore default SIGPIPE handling so piping to `head` etc. terminates
    // quietly instead of panicking on a broken stdout.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();
    let owner_explicit = cli.owner.is_some();
    let owner = cli
        .owner
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "anonymous".to_string());
    let server = cli.server.trim_end_matches('/').to_string();
    let theme = Theme::new(if cli.json {
        RenderMode::Plain
    } else {
        RenderMode::detect()
    });
    let client = match http::Client::new(&server, Duration::from_secs(30)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", theme.alert(&format!("error: {e}")));
            std::process::exit(2);
        }
    };
    let ctx = Ctx {
        client,
        server,
        owner,
        owner_explicit,
        api_key: cli.api_key,
        json: cli.json,
        theme,
    };

    let result = match cli.command {
        Command::Acquire {
            resource,
            mode,
            lease,
            priority,
            wait,
            wait_timeout,
            if_epoch,
            if_not_held_by,
            metadata,
        } => cmd_acquire(
            &ctx,
            &resource,
            &mode,
            lease.as_deref(),
            &priority,
            wait,
            wait_timeout,
            metadata.as_deref(),
            if_epoch,
            if_not_held_by.as_deref(),
        ),
        Command::Release { resource } => cmd_release(&ctx, &resource),
        Command::Renew { resource } => cmd_renew(&ctx, &resource),
        Command::Heartbeat { resources } => cmd_heartbeat(&ctx, &resources),
        Command::Inspect { resource } => cmd_inspect(&ctx, &resource),
        Command::Queue { resource } => cmd_queue(&ctx, &resource),
        Command::Transfer { resource, to } => cmd_transfer(&ctx, &resource, &to),
        Command::Steal { resource, reason } => cmd_steal(&ctx, &resource, reason.as_deref()),
        Command::Promote { resource, mode } => cmd_promote(&ctx, &resource, mode.as_deref()),
        Command::Downgrade { resource, mode } => cmd_downgrade(&ctx, &resource, mode.as_deref()),
        Command::Leases => cmd_leases(&ctx),
        Command::Events { limit } => cmd_events(&ctx, limit),
        Command::Audit { limit } => cmd_audit(&ctx, limit),
        Command::Metrics => cmd_metrics(&ctx),
        Command::Trust { command } => run_trust_command(&ctx.theme, command),
    };

    if let Err(e) = result {
        eprintln!("{}", ctx.theme.alert(&format!("error: {e}")));
        std::process::exit(1);
    }
}
