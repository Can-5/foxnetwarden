//! Yerel sezgisel şüphe puanlayıcı (0-100). Bulut veya dış servis yok.

use crate::blocklist::{blocklist_match, MatchResult};
use crate::collector::Connection;

/// `IP:port` veya `domain:port` uç noktasından sunucu adresini çıkarır.
/// IPv6 `[::1]:443` biçimini de destekler.
fn host_from_endpoint(endpoint: &str) -> &str {
    if let Some(rest) = endpoint.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(endpoint);
    }
    match endpoint.rfind(':') {
        Some(i) if endpoint[i + 1..].chars().all(|c| c.is_ascii_digit()) => &endpoint[..i],
        _ => endpoint,
    }
}

/// Tek başına şüphe puanı (bağlam sayısı yok).
pub fn analyzer_score(conn: &Connection) -> u8 {
    analyzer_score_with_targets(conn, 0)
}

/// Bağlamlı puan: `distinct_targets` aynı sürecin farklı hedef sayısıdır
/// (top-talker sezgisi). Puan 0-100 aralığında kırpılır.
pub fn analyzer_score_with_targets(conn: &Connection, distinct_targets: usize) -> u8 {
    let host = host_from_endpoint(&conn.remote);
    let mut score: u8 = match blocklist_match(host) {
        MatchResult::Malware => 90,
        MatchResult::Tracker => 60,
        MatchResult::Clean => 0,
    };

    // Top-talker: tek süreçten çok sayıda farklı hedef.
    if distinct_targets >= 10 {
        score = score.saturating_add(30);
    }

    score.min(100)
}
