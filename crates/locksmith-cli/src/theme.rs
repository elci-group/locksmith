//! Lock-themed styling for human-readable CLI output.
//!
//! Every subcommand's non-JSON output routes through here so the same
//! vocabulary means the same thing everywhere: an icon compresses a
//! target's lock state into one glyph, and an owner's color is the same
//! wherever that owner appears, across every command and every process
//! (it's a pure hash of the owner string — no shared state, no lookup
//! table to keep in sync).
//!
//! Three render forms, chosen once at startup and never mixed:
//! * `Rich`  — emoji icons + 256-color ANSI, for a real unicode terminal.
//! * `Ascii` — bracketed text icons + ANSI color, for a color terminal
//!   whose locale doesn't advertise UTF-8.
//! * `Plain` — bracketed text icons, no ANSI at all. Used for `NO_COLOR`,
//!   non-terminal stdout (pipes, redirection, CI logs), and is always the
//!   safe fallback: nothing here ever assumes a form it hasn't detected.
//!
//! `--json` bypasses all of this upstream (in `main.rs`) — machine output
//! stays exactly the API's JSON, uncolored and unannotated.

use std::io::IsTerminal;

use locksmith_core::LockMode;

/// A target's relationship to the lease/queue entry being described.
/// Drives the style *variant*: solid+bold for a holder, dim for a waiter —
/// same owner color either way, so "who" reads identically and "how" reads
/// from weight alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// Currently holds the lease.
    Holding,
    /// Queued, attempting to acquire.
    Attempting,
}

/// What a target's status line is reporting. One glyph per state — this is
/// the "semantic compression": a reader scanning a column of these should
/// not need the word next to it.
#[derive(Clone, Copy, Debug)]
pub enum Status {
    /// No lease held on the target.
    Free,
    /// Held, in the given lock mode.
    Held(LockMode),
    /// Queued behind a conflicting holder.
    Queued,
    /// Forcibly revoked from its previous holder.
    Stolen,
    /// A held lease's mode was strengthened.
    Promoted,
    /// A held lease's mode was weakened.
    Downgraded,
    /// A secret sealed at rest.
    Sealed,
    /// A secret unsealed back to plaintext.
    Unsealed,
    /// A lease's heartbeat was refreshed (still alive, not a state change).
    Heartbeat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderMode {
    Rich,
    Ascii,
    Plain,
}

impl RenderMode {
    /// Detect once at startup from `NO_COLOR`, whether stdout is a
    /// terminal, and whether the locale advertises UTF-8. Never guess
    /// harder than that — a wrong guess in the "fancier" direction breaks
    /// output for someone piping to a file or grepping in a dumb terminal,
    /// which is a worse failure than a plainer-than-necessary render.
    pub fn detect() -> RenderMode {
        if std::env::var_os("NO_COLOR").is_some() {
            return RenderMode::Plain;
        }
        if !std::io::stdout().is_terminal() {
            return RenderMode::Plain;
        }
        let unicode = ["LC_ALL", "LC_CTYPE", "LANG"].iter().any(|var| {
            std::env::var(var)
                .map(|v| v.to_uppercase().contains("UTF-8") || v.to_uppercase().contains("UTF8"))
                .unwrap_or(false)
        });
        if unicode {
            RenderMode::Rich
        } else {
            RenderMode::Ascii
        }
    }
}

/// Distinct hues for owner identity, chosen to stay clear of the two
/// colors this module reserves for state (green for free, red for
/// stolen/alert). Order doesn't matter — the mapping is `hash(owner) %
/// len`, not position-assigned.
const OWNER_PALETTE: &[u8] = &[39, 208, 135, 178, 44, 205, 111, 214, 87, 172];

const GREEN: u8 = 41;
const RED: u8 = 203;
const GRAY: u8 = 244;

fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub struct Theme {
    mode: RenderMode,
}

impl Theme {
    pub fn new(mode: RenderMode) -> Self {
        Theme { mode }
    }

    fn color(&self, code: u8, bold: bool, dim: bool, text: &str) -> String {
        if self.mode == RenderMode::Plain {
            return text.to_string();
        }
        let weight = if bold {
            "1;"
        } else if dim {
            "2;"
        } else {
            ""
        };
        format!("\x1b[{weight}38;5;{code}m{text}\x1b[0m")
    }

    /// This owner's color, stable across processes and commands: a pure
    /// hash of the name, not an assignment that could drift between runs.
    fn owner_code(&self, owner: &str) -> u8 {
        OWNER_PALETTE[(fnv1a(owner) as usize) % OWNER_PALETTE.len()]
    }

    /// Style an owner name per [`Variant`]: bold for a holder, dim for a
    /// waiter, same hue either way.
    pub fn owner(&self, owner: &str, variant: Variant) -> String {
        let code = self.owner_code(owner);
        match variant {
            Variant::Holding => self.color(code, true, false, owner),
            Variant::Attempting => self.color(code, false, true, owner),
        }
    }

    /// Icon for a target's status — the one glyph a reader should be able
    /// to scan a column of without reading the label next to it.
    pub fn icon(&self, status: Status) -> &'static str {
        use Status::*;
        match (self.mode, status) {
            (RenderMode::Plain, Free) => "(open)",
            (RenderMode::Plain, Held(LockMode::Exclusive)) => "[LOCK]",
            (RenderMode::Plain, Held(LockMode::Shared)) => "[SHARE]",
            (RenderMode::Plain, Held(LockMode::Intent)) => "[INTENT]",
            (RenderMode::Plain, Queued) => "[WAIT]",
            (RenderMode::Plain, Stolen) => "[STOLEN]",
            (RenderMode::Plain, Promoted) => "[UP]",
            (RenderMode::Plain, Downgraded) => "[DOWN]",
            (RenderMode::Plain, Sealed) => "[SEALED]",
            (RenderMode::Plain, Unsealed) => "[PLAIN]",
            (RenderMode::Plain, Heartbeat) => "[hb]",

            (RenderMode::Ascii, Free) => "( )",
            (RenderMode::Ascii, Held(LockMode::Exclusive)) => "[X]",
            (RenderMode::Ascii, Held(LockMode::Shared)) => "[S]",
            (RenderMode::Ascii, Held(LockMode::Intent)) => "[I]",
            (RenderMode::Ascii, Queued) => "[.]",
            (RenderMode::Ascii, Stolen) => "[!]",
            (RenderMode::Ascii, Promoted) => "[^]",
            (RenderMode::Ascii, Downgraded) => "[v]",
            (RenderMode::Ascii, Sealed) => "[#]",
            (RenderMode::Ascii, Unsealed) => "[o]",
            (RenderMode::Ascii, Heartbeat) => "(.)",

            (RenderMode::Rich, Free) => "🔓",
            (RenderMode::Rich, Held(LockMode::Exclusive)) => "🔒",
            (RenderMode::Rich, Held(LockMode::Shared)) => "🔑",
            (RenderMode::Rich, Held(LockMode::Intent)) => "🗝️",
            (RenderMode::Rich, Queued) => "⏳",
            (RenderMode::Rich, Stolen) => "⚡",
            (RenderMode::Rich, Promoted) => "⬆️",
            (RenderMode::Rich, Downgraded) => "⬇️",
            (RenderMode::Rich, Sealed) => "🔐",
            (RenderMode::Rich, Unsealed) => "🔓",
            (RenderMode::Rich, Heartbeat) => "💓",
        }
    }

    /// The icon colored for state rather than identity: green for free
    /// (nothing to compress further — nobody owns it), red for stolen or
    /// an alert condition. Reserved colors, never used for an owner.
    pub fn status_icon(&self, status: Status) -> String {
        let icon = self.icon(status);
        match status {
            Status::Free | Status::Heartbeat | Status::Sealed => {
                self.color(GREEN, true, false, icon)
            }
            Status::Stolen => self.color(RED, true, false, icon),
            Status::Unsealed => self.color(GRAY, false, true, icon),
            _ => icon.to_string(),
        }
    }

    /// A held/queued lock icon colored to match its owner, so the glyph
    /// and the name it belongs to visually agree at a glance.
    pub fn owned_icon(&self, status: Status, owner: &str, variant: Variant) -> String {
        let icon = self.icon(status);
        let code = self.owner_code(owner);
        match variant {
            Variant::Holding => self.color(code, true, false, icon),
            Variant::Attempting => self.color(code, false, true, icon),
        }
    }

    pub fn dim(&self, text: &str) -> String {
        self.color(GRAY, false, true, text)
    }

    pub fn alert(&self, text: &str) -> String {
        self.color(RED, true, false, text)
    }

    pub fn good(&self, text: &str) -> String {
        self.color(GREEN, true, false, text)
    }

    pub fn spinner(&self) -> Spinner {
        let frames: &'static [&'static str] = match self.mode {
            RenderMode::Rich => &["🔓", "🔐", "🔒", "🔐"],
            RenderMode::Ascii | RenderMode::Plain => &["[ ]", "[-]", "[x]", "[-]"],
        };
        Spinner { frames, i: 0 }
    }

    /// Animation is a stderr-interactivity question, independent of
    /// whether stdout (the data channel) is a terminal: `--wait` writes
    /// its progress to stderr, so that's what must be a TTY for a
    /// carriage-return spinner to render instead of spamming scrollback.
    pub fn animate(&self) -> bool {
        self.mode != RenderMode::Plain && std::io::stderr().is_terminal()
    }
}

/// Cycles through lock-themed frames to depict "attempting to close the
/// lock" while a `--wait` acquire is queued. Rendered as a single
/// self-overwriting line so a long wait doesn't flood the terminal.
pub struct Spinner {
    frames: &'static [&'static str],
    i: usize,
}

impl Spinner {
    pub fn tick(&mut self) -> &'static str {
        let f = self.frames[self.i % self.frames.len()];
        self.i += 1;
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_color_is_stable() {
        let theme = Theme::new(RenderMode::Rich);
        let a1 = theme.owner("hermes", Variant::Holding);
        let a2 = theme.owner("hermes", Variant::Holding);
        assert_eq!(a1, a2);
    }

    #[test]
    fn different_owners_can_collide_but_usually_dont() {
        // Not a correctness requirement (hashing can collide), just a
        // sanity check that the palette actually varies in practice.
        let theme = Theme::new(RenderMode::Rich);
        let names = ["hermes", "openclaw", "kaptaind", "admin", "ci"];
        let colors: std::collections::HashSet<_> =
            names.iter().map(|n| theme.owner_code(n)).collect();
        assert!(colors.len() > 1);
    }

    #[test]
    fn plain_mode_emits_no_ansi() {
        let theme = Theme::new(RenderMode::Plain);
        let styled = theme.owner("hermes", Variant::Holding);
        assert_eq!(styled, "hermes");
        assert!(!theme.status_icon(Status::Free).contains('\x1b'));
    }

    #[test]
    fn variant_changes_weight_not_hue() {
        let theme = Theme::new(RenderMode::Rich);
        let holding = theme.owner("hermes", Variant::Holding);
        let attempting = theme.owner("hermes", Variant::Attempting);
        assert_ne!(holding, attempting);
        assert!(holding.contains("1;38;5;"));
        assert!(attempting.contains("2;38;5;"));
    }

    #[test]
    fn spinner_cycles() {
        let theme = Theme::new(RenderMode::Rich);
        let mut s = theme.spinner();
        let first = s.tick();
        let frames: Vec<_> = (0..8).map(|_| s.tick()).collect();
        assert!(frames.contains(&first));
    }
}
