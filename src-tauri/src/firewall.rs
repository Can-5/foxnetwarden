//! nftables firewall wrapper. All privileged writes go through `pkexec`
//! (per-action password, no cached trust). Rule targets are strictly
//! validated to prevent shell/nft expression injection.

use std::path::{Path, PathBuf};
use std::process::Command;

pub const TABLE: &str = "foxnetwarden";
pub const CHAIN_BLOCK: &str = "block";
pub const CHAIN_KILLSWITCH: &str = "killswitch";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Block,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Cidr(String),
    Domain(String),
    Port(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallError {
    PkexecMissing,
    NftMissing,
    InvalidTarget(String),
    NftFailed(String),
    NoRoot,
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallError::PkexecMissing => write!(f, "yetki aracı (pkexec) bulunamadı"),
            FirewallError::NftMissing => write!(f, "nft bulunamadı"),
            FirewallError::InvalidTarget(s) => write!(f, "geçersiz hedef: {s}"),
            FirewallError::NftFailed(s) => write!(f, "nft hatası: {s}"),
            FirewallError::NoRoot => write!(f, "root yetkisi gerekli"),
        }
    }
}

impl std::error::Error for FirewallError {}

/// Validate a rule target string against the constrained rule grammar.
/// Only CIDR (v4/v6), domain, or numeric port are accepted — never free-form nft.
pub fn validate_target(s: &str) -> Result<Target, FirewallError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(FirewallError::InvalidTarget(s.to_string()));
    }
    // Reject any shell/nft metacharacter outright.
    const BAD: &[char] = &[
        ';', '&', '|', '$', '(', ')', '{', '}', '<', '>', '\'', '"', '`', '\\', '\n', '\r', ' ',
        '\t', '#', '!', '*', '?',
    ];
    if s.chars().any(|c| BAD.contains(&c)) {
        return Err(FirewallError::InvalidTarget(s.to_string()));
    }

    // Pure numeric port (0-65535).
    if let Ok(port) = s.parse::<u16>() {
        return Ok(Target::Port(port));
    }

    // CIDR / IP: only digits, '.', ':', letters a-f/A-F (hex for IPv6) and '/'.
    if s.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':' || c == '/' || c.is_ascii_hexdigit() || c == 'a' || c == 'f')
        && (s.contains('.') || s.contains(':'))
    {
        return Ok(Target::Cidr(s.to_string()));
    }

    // Domain: labels of [A-Za-z0-9-] separated by dots, at least one dot.
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() >= 2
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
    {
        return Ok(Target::Domain(s.to_ascii_lowercase()));
    }

    Err(FirewallError::InvalidTarget(s.to_string()))
}

fn action_word(action: &Action) -> &'static str {
    match action {
        Action::Block => "drop",
        Action::Allow => "accept",
    }
}

/// Canonical nft set name for a domain (dots/dashes → underscores). Shared by
/// rule generation and set creation so a domain rule always matches its set.
pub fn set_name(domain: &str) -> String {
    format!("{}_set", domain.to_ascii_lowercase().replace(['.', '-'], "_"))
}

/// Bootstrap the table plus `block` as a BASE chain (hook output, policy
/// accept). nft only evaluates base chains — a regular chain is inert unless
/// something jumps to it, which is why blocking previously did nothing.
pub fn nft_table_bootstrap(rule: &str) -> String {
    format!(
        "add table inet {TABLE}\nadd chain inet {TABLE} {CHAIN_BLOCK} {{ type filter hook output priority 0; policy accept; }}\n{rule}"
    )
}

/// Generate an `add rule` nft line for a validated target.
pub fn nft_rule_add(target: &Target, action: Action) -> String {
    let act = action_word(&action);
    match target {
        Target::Cidr(cidr) => {
            if cidr.contains(':') {
                format!("add rule inet {TABLE} {CHAIN_BLOCK} ip6 daddr {cidr} {act}")
            } else {
                format!("add rule inet {TABLE} {CHAIN_BLOCK} ip daddr {cidr} {act}")
            }
        }
        Target::Domain(domain) => {
            format!("add rule inet {TABLE} {CHAIN_BLOCK} ip daddr @{} {act}", set_name(domain))
        }
        Target::Port(port) => format!(
            "add rule inet {TABLE} {CHAIN_BLOCK} tcp dport {port} {act}"
        ),
    }
}

/// Generate a `delete rule ... handle N` line. The handle must be numeric.
pub fn nft_rule_remove(handle: &str) -> Result<String, FirewallError> {
    if handle.is_empty() || !handle.chars().all(|c| c.is_ascii_digit()) {
        return Err(FirewallError::InvalidTarget(handle.to_string()));
    }
    Ok(format!("delete rule inet {TABLE} {CHAIN_BLOCK} handle {handle}"))
}

/// Generate the kill-switch script. Enabling installs `output` and `forward`
/// hooks at priority -300 with `policy drop` — before any allow rule can match
/// and covering locally-generated AND forwarded (Docker/VM/NAT) traffic — with
/// no established/loopback/DNS exceptions, so nothing leaks. Under `inet` both
/// IPv4 and IPv6 are covered. Disabling deletes only the killswitch chain,
/// leaving the rest of the table intact, and is session-only (nft is not persisted).
pub fn nft_killswitch_script(active: bool) -> String {
    if active {
        format!(
            "table inet {TABLE} {{\n  chain {CHAIN_KILLSWITCH} {{\n    type filter hook output priority -300; policy drop;\n  }}\n  chain {CHAIN_KILLSWITCH}_fwd {{\n    type filter hook forward priority -300; policy drop;\n  }}\n}}"
        )
    } else {
        format!("delete chain inet {TABLE} {CHAIN_KILLSWITCH}\ndelete chain inet {TABLE} {CHAIN_KILLSWITCH}_fwd")
    }
}

/// The argv shape used to run nft through pkexec.
pub fn pkexec_nft_args() -> Vec<String> {
    vec!["pkexec".into(), "nft".into(), "-f".into(), "-".into()]
}

/// Resolve a pkexec binary at a known path. Separated from shell-out so the
/// "missing pkexec" failure path is testable without elevated privileges.
pub fn resolve_pkexec(candidate: &str) -> Result<PathBuf, FirewallError> {
    let p = Path::new(candidate);
    if p.is_file() {
        Ok(p.to_path_buf())
    } else {
        Err(FirewallError::PkexecMissing)
    }
}

fn find_pkexec() -> Result<PathBuf, FirewallError> {
    for candidate in ["/usr/bin/pkexec", "/bin/pkexec"] {
        if let Ok(p) = resolve_pkexec(candidate) {
            return Ok(p);
        }
    }
    Err(FirewallError::PkexecMissing)
}

/// Feed an nft script to `pkexec nft -f -` via stdin. No shell is involved.
pub fn run_nft_script(script: &str) -> Result<(), FirewallError> {
    use std::io::Write;
    let pkexec = find_pkexec()?;
    let args = pkexec_nft_args();
    let mut child = Command::new(&pkexec)
        .args(&args[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| FirewallError::NftFailed(e.to_string()))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| FirewallError::NftFailed(e.to_string()))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| FirewallError::NftFailed(e.to_string()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(FirewallError::NftFailed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
    }
}

/// Status of the nftables table (read-only; does not need root).
pub fn fw_status() -> Result<String, FirewallError> {
    if Command::new("nft").arg("list").arg("table").arg(format!("inet {TABLE}")).output().is_ok() {
        Ok(String::from("active"))
    } else {
        Ok(String::from("unknown"))
    }
}

/// Add a block/allow rule. Privileged; returns whether elevation succeeded.
pub fn rule_add(target: &str, action: Action) -> Result<(), FirewallError> {
    let t = validate_target(target)?;
    let script = nft_table_bootstrap(&nft_rule_add(&t, action));
    run_nft_script(&script)
}

/// Remove a rule by numeric handle.
pub fn rule_remove(id: &str) -> Result<(), FirewallError> {
    let line = nft_rule_remove(id)?;
    run_nft_script(&line)
}

/// Enable or disable the kill switch.
pub fn killswitch_set(active: bool) -> Result<(), FirewallError> {
    run_nft_script(&nft_killswitch_script(active))
}
