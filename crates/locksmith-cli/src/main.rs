//! locksmith — command line client for the Locksmith coordination daemon.

mod http;

use std::time::Duration;

use clap::{Parser, Subcommand};
use serde::Deserialize;

use locksmith_core::{
    AcquireOutcome, AuditRecord, Event, Lease, LockMode, MetricsSnapshot, Priority, QueueEntry,
    ResourceView,
};

/// Locksmith CLI: workspace locking and coordination.
#[derive(Parser)]
#[command(name = "locksmith", version, about)]
struct Cli {
    /// Daemon base URL.
    #[arg(long, env = "LOCKSMITH_SERVER", default_value = "http://127.0.0.1:7700", global = true)]
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
}

struct Ctx {
    client: http::Client,
    server: String,
    owner: String,
    owner_explicit: bool,
    api_key: Option<String>,
    json: bool,
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
            format!("cannot reach daemon at {}: {e}\n  is locksmithd running?", self.server)
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
        self.decode(
            self.client
                .post_json(path, &text, self.api_key.as_deref()),
        )
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
    let (label, abs) = if delta >= 0 { ("in", delta) } else { ("", -delta) };
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

fn print_lease(lease: &Lease) {
    println!("Owner:    {}", lease.owner);
    println!("Mode:     {}", lease.mode.as_str());
    println!("Since:    {} UTC", fmt_hms(lease.acquired_at));
    println!(
        "Expires:  {} UTC ({})",
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
) -> Result<(), String> {
    if LockMode::parse(mode).is_none() {
        return Err(format!("unknown mode '{mode}' (exclusive|shared|intent)"));
    }
    if Priority::parse(priority).is_none() {
        return Err(format!("unknown priority '{priority}' (low|normal|high|critical)"));
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
    });

    let started = std::time::Instant::now();
    let timeout = Duration::from_secs(wait_timeout);
    let mut last_position: Option<usize> = None;
    loop {
        let outcome: AcquireOutcome = ctx.post("/v1/acquire", &body)?;
        match outcome {
            AcquireOutcome::Granted { lease } => {
                if ctx.json {
                    println!("{}", serde_json::to_string_pretty(&lease).unwrap());
                } else {
                    println!("Acquired {resource}");
                    print_lease(&lease);
                }
                return Ok(());
            }
            AcquireOutcome::Held { lease } => {
                if ctx.json {
                    println!("{}", serde_json::to_string_pretty(&lease).unwrap());
                } else {
                    println!("Already held {resource}");
                    print_lease(&lease);
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
                        println!("Queued for {resource} at position {position}");
                        println!("Owner:    {} (holding)", holding_summary(ctx, resource));
                        println!("Mode:     {}", entry.mode.as_str());
                        println!("Hint:     re-run with --wait to block until granted");
                    }
                    return Ok(());
                }
                if last_position != Some(position) {
                    eprintln!("waiting for {resource}: queue position {position}");
                    last_position = Some(position);
                }
                if started.elapsed() > timeout {
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
            .map(|l| format!("{} ({})", l.owner, l.mode.as_str()))
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
        println!("Released {resource} ({})", ctx.owner);
        for lease in &resp.promoted {
            println!(
                "Promoted: {} now holds {} ({})",
                lease.owner,
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
        println!("Renewed {resource}");
        print_lease(&lease);
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
        println!("Heartbeat: {} lease(s) refreshed for {}", resp.leases_refreshed, ctx.owner);
    }
    Ok(())
}

fn cmd_inspect(ctx: &Ctx, resource: &str) -> Result<(), String> {
    let view: ResourceView = ctx.get("/v1/inspect", &[("resource", resource)])?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&view).unwrap());
        return Ok(());
    }
    println!("Resource: {resource}");
    if view.leases.is_empty() {
        println!("Owner:    (none — unlocked)");
    } else {
        for lease in &view.leases {
            print_lease(lease);
            println!();
        }
    }
    if !view.queue.is_empty() {
        println!("Queue:");
        for (i, entry) in view.queue.iter().enumerate() {
            println!(
                "  {}. {} ({}, {:?} priority)",
                i + 1,
                entry.owner,
                entry.mode.as_str(),
                entry.priority
            );
        }
    }
    if !view.ancestor_locks.is_empty() {
        println!("Ancestor locks:");
        for lease in &view.ancestor_locks {
            println!(
                "  {} held by {} ({})",
                lease.resource,
                lease.owner,
                lease.mode.as_str()
            );
        }
    }
    if !view.descendant_locks.is_empty() {
        println!("Descendant locks:");
        for lease in &view.descendant_locks {
            println!(
                "  {} held by {} ({})",
                lease.resource,
                lease.owner,
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
        println!("Queue for {resource} is empty");
    } else {
        println!("Queue for {resource}:");
        for (i, entry) in queue.iter().enumerate() {
            println!(
                "  {}. {} ({}, {:?} priority, waiting since {} UTC)",
                i + 1,
                entry.owner,
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
        println!("Transferred {resource}: {} -> {}", ctx.owner, to);
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
        println!("Stole {resource}");
        print_lease(&lease);
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
        println!("Promoted {resource} to {}", lease.mode.as_str());
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
        println!("Downgraded {resource}");
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
        println!("No active leases");
    } else {
        println!("{:<40} {:<20} {:<10} EXPIRES", "RESOURCE", "OWNER", "MODE");
        for lease in &leases {
            println!(
                "{:<40} {:<20} {:<10} {} ({})",
                lease.resource,
                lease.owner,
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
        println!(
            "#{:>5} {}  {:?}  {}  {}",
            event.seq,
            fmt_hms(event.ts),
            event.kind,
            event.resource,
            event.owner
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
        println!(
            "{}  {:<10} {:<20} {}{}",
            fmt_hms(record.ts),
            record.action,
            record.owner,
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
    println!("Active leases:    {}", snapshot.active_leases);
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
    Ok(())
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
    let client = match http::Client::new(&server, Duration::from_secs(30)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
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
    };

    let result = match cli.command {
        Command::Acquire {
            resource,
            mode,
            lease,
            priority,
            wait,
            wait_timeout,
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
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
