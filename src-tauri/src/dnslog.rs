//! Opt-in DNS query log via `systemd-resolved` debug journal.
//!
//! Normal `systemd-resolved` logging records server health but NOT which
//! domains were queried. Query lines only appear when debug logging is on.
//! When debug is off (or browsers bypass resolved via DoH), the module reports
//! an honest "invisible" state instead of pretending it sees DNS traffic.

use serde::Serialize;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

/// One observed DNS query.
#[derive(Debug, Clone, Serialize)]
pub struct DnsEvent {
    pub timestamp: String,
    pub domain: String,
    pub query_type: String,
}

/// Aggregated DNS status for the UI.
#[derive(Debug, Clone, Serialize)]
pub struct DnsStatus {
    pub enabled: bool,
    pub visible: bool,
    pub count: usize,
}

/// Whether resolved debug parsing is opted-in (session-only, no persistence).
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Parse `journalctl -u systemd-resolved -o short-iso` lines.
///
/// Recognizes debug lines of the form:
///   `... systemd-resolved[NNN]: Looking up RR for <domain> IN <TYPE>.`
/// All other lines (server health, sent-message, etc.) are ignored.
pub fn parse_resolved_lines(text: &str) -> Vec<DnsEvent> {
    let mut events = Vec::new();
    const MARKER: &str = "Looking up RR for ";

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rest = match line.split_once(MARKER) {
            Some((_, r)) => r,
            None => continue,
        };
        let (domain, tail) = match rest.split_once(" IN ") {
            Some((d, t)) => (d.trim(), t),
            None => continue,
        };
        if domain.is_empty() {
            continue;
        }
        let query_type = tail.trim_end_matches('.').trim().to_string();
        if query_type.is_empty() {
            continue;
        }
        let timestamp = line.split_whitespace().next().unwrap_or("").to_string();
        events.push(DnsEvent {
            timestamp,
            domain: domain.to_string(),
            query_type,
        });
    }
    events
}

/// Honest invisibility rule: no data when opted out, and no data when
/// opted in but no query lines are present (debug off / DoH bypass).
pub fn is_invisible(enabled: bool, event_count: usize) -> bool {
    !enabled || event_count == 0
}

/// Pure status derivation, testable without running journalctl.
pub fn dns_status_from(enabled: bool, event_count: usize) -> (bool, bool) {
    (enabled, !is_invisible(enabled, event_count))
}

/// Enable or disable resolved debug parsing. Returns the new state.
pub fn dns_mode_set(enabled: bool) -> bool {
    ENABLED.store(enabled, Ordering::SeqCst);
    enabled
}

/// Toggle the mode; returns the new state.
pub fn dns_mode_toggle() -> bool {
    let next = !ENABLED.load(Ordering::SeqCst);
    ENABLED.store(next, Ordering::SeqCst);
    next
}

/// Current opted-in state.
pub fn dns_mode_enabled() -> bool {
    ENABLED.load(Ordering::SeqCst)
}

/// Read recent resolved journal and parse query lines. Empty when not opted in,
/// when journalctl is unavailable, or when debug logging produced no queries.
pub fn dns_events() -> Vec<DnsEvent> {
    if !dns_mode_enabled() {
        return Vec::new();
    }
    let output = Command::new("journalctl")
        .args(["-u", "systemd-resolved", "--no-pager", "-o", "short-iso", "-n", "500"])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            parse_resolved_lines(&String::from_utf8_lossy(&out.stdout))
        }
        _ => Vec::new(),
    }
}

/// Full status: enabled flag + whether queries are actually visible.
pub fn dns_status() -> DnsStatus {
    let enabled = dns_mode_enabled();
    let count = dns_events().len();
    let (_, visible) = dns_status_from(enabled, count);
    DnsStatus {
        enabled,
        visible,
        count,
    }
}
