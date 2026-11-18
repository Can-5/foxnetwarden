//! Domain → IP/CIDR resolution for nft sets. Resolves via the system
//! resolver (`ToSocketAddrs`), generates nft `set` scripts, and supports
//! periodic re-resolution so stale CDN IPs expire. No cloud, no external
//! service — only the machine's own resolver.

use crate::firewall::{run_nft_script, set_name, FirewallError, TABLE};
use std::net::{IpAddr, ToSocketAddrs};

/// Resolve a domain name to its current IP addresses via the system resolver.
/// Returns an empty list (not an error) when the name cannot be resolved, so
/// a single failed lookup never crashes the refresh loop.
pub fn resolve_domain(domain: &str) -> Vec<IpAddr> {
    let authority = if domain.contains(':') {
        domain.to_string()
    } else {
        format!("{domain}:443")
    };
    match authority.to_socket_addrs() {
        Ok(addrs) => {
            let mut seen = Vec::new();
            for addr in addrs {
                if !seen.contains(&addr.ip()) {
                    seen.push(addr.ip());
                }
            }
            seen
        }
        Err(_) => Vec::new(),
    }
}

/// Generate the nft script that creates/updates an nft set holding the given
/// IPs. `flush` removes stale entries before re-adding — this is what lets a
/// rotated CDN IP be replaced on the next re-resolution.
pub fn nft_domain_set_script(domain: &str, ips: &[IpAddr]) -> String {
    let sname = set_name(domain);
    let mut script = format!(
        "add table inet {TABLE}\nadd set inet {TABLE} {sname} {{ type ipv4_addr; }}\nflush set inet {TABLE} {sname}\n"
    );
    for ip in ips {
        if let IpAddr::V4(v4) = ip {
            script.push_str(&format!("add element inet {TABLE} {sname} {{ {v4} }}\n"));
        }
    }
    script
}

/// Resolve a domain and sync its nft set in one privileged step.
pub fn domainblock_sync(domains: &[String]) -> Result<(), FirewallError> {
    let mut script = String::new();
    for domain in domains {
        let ips = resolve_domain(domain);
        script.push_str(&nft_domain_set_script(domain, &ips));
    }
    run_nft_script(&script)
}
