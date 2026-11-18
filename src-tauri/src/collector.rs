use serde::Serialize;
use std::process::Command;

/// One observed network connection, as reported by `ss -tunp`.
#[derive(Debug, Clone, Serialize)]
pub struct Connection {
    pub pid: Option<u32>,
    pub name: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub duration: u64,
}

/// Parse the trailing `users:(("name",pid=N,fd=M))` process field from an `ss` line.
///
/// Returns `(pid, name)`. When no process info is present (or the caller lacks
/// ptrace permission for another user's socket) pid is `None` and name is `"?"`.
pub fn parse_process(process_field: &str) -> (Option<u32>, String) {
    let pid = process_field
        .split("pid=")
        .nth(1)
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse::<u32>().ok());

    let name = process_field
        .split("users:((")
        .nth(1)
        .and_then(|s| s.split('"').nth(1))
        .unwrap_or("?")
        .to_string();

    (pid, name)
}

/// Run `ss -tunp` and parse every connection into [`Connection`] records.
/// Processes owned by other UIDs show `pid: None`, `name: "?"`.
pub fn live_connections() -> Result<Vec<Connection>, String> {
    let output = Command::new("ss")
        .args(["-tunp"])
        .output()
        .map_err(|e| format!("ss failed to start: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();

    for line in stdout.lines().skip(1) {
        // skip header
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Netid State Recv-Q Send-Q Local:Port Peer:Port [Process...]
        // ss separates columns with runs of whitespace; split_whitespace collapses them.
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let state = parts[1].to_string();
        let local = parts[4].to_string();
        let remote = parts[5].to_string();
        let process_field = if parts.len() >= 7 {
            parts[6..].join(" ")
        } else {
            "".to_string()
        };

        let (pid, name) = if !process_field.is_empty() {
            parse_process(&process_field)
        } else {
            (None, "?".to_string())
        };

        connections.push(Connection {
            pid,
            name,
            local,
            remote,
            state,
            duration: 0,
        });
    }

    Ok(connections)
}
