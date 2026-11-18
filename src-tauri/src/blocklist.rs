//! Vendored (pakete gömülü) tracker / kötü amaçlı alan adı ve IP listeleri.
//! Çevrimdışı çalışır; internetten güncelleme yok (Faz 2).

/// Bir hedefin blok listesiyle eşleşme sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchResult {
    Clean,
    Tracker,
    Malware,
}

/// Tam eşleşen tracker alan adları (alt domainleri kapsamaz).
const TRACKER_EXACT: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "facebook.net",
    "connect.facebook.net",
    "scorecardresearch.com",
    "quantserve.com",
    "hotjar.com",
    "segment.io",
    "mixpanel.com",
];

/// Joker tracker alan adları: girdi taban domain veya herhangi bir alt domain olabilir.
const TRACKER_WILDCARD: &[&str] = &[
    "doubleclick.net",
    "googleadservices.com",
    "googlesyndication.com",
    "adservice.google.com",
    "facebook.com",
    "twitter.com",
    "amazon-adsystem.com",
];

/// Bilinen kötü amaçlı IP'ler (TEST-NET adresleri örnek girdi olarak gömülüdür).
const MALWARE_IPS: &[&str] = &[
    "192.0.2.66",
    "192.0.2.123",
    "198.51.100.44",
    "203.0.113.77",
];

/// Bir domain veya IP'yi gömülü listelerle eşleştirir (büyük/küçük harf duyarsız).
///
/// - Tam tracker girdileri yalnızca alan adının kendisiyle eşleşir.
/// - Joker tracker girdileri taban domain ve `*.taban` alt domainleriyle eşleşir.
/// - Kötü amaçlı IP'ler tam IP eşleşmesiyle kontrol edilir.
pub fn blocklist_match(target: &str) -> MatchResult {
    let t = target.trim().trim_end_matches('.').to_lowercase();
    if t.is_empty() {
        return MatchResult::Clean;
    }

    if MALWARE_IPS.iter().any(|ip| *ip == t) {
        return MatchResult::Malware;
    }

    if TRACKER_EXACT.iter().any(|d| *d == t) {
        return MatchResult::Tracker;
    }

    for base in TRACKER_WILDCARD {
        if t == *base || t.ends_with(&format!(".{}", base)) {
            return MatchResult::Tracker;
        }
    }

    MatchResult::Clean
}

/// Gömülü liste istatistikleri (UI "blocklist_stats" için).
pub fn blocklist_stats() -> (usize, usize, usize) {
    (
        TRACKER_EXACT.len(),
        TRACKER_WILDCARD.len(),
        MALWARE_IPS.len(),
    )
}
