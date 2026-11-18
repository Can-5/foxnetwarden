use foxnetwarden::blocklist::{blocklist_match, MatchResult};

#[test]
fn test_blocklist_exact_tracker_domain() {
    // Exact vendored entry: matches the domain exactly.
    assert_eq!(blocklist_match("google-analytics.com"), MatchResult::Tracker);
    // Exact entries must not match arbitrary subdomains.
    assert_eq!(
        blocklist_match("foo.google-analytics.com"),
        MatchResult::Clean
    );
}

#[test]
fn test_blocklist_wildcard_subdomain() {
    // Wildcard vendored entry: *.doubleclick.net matches base and any subdomain.
    assert_eq!(blocklist_match("ad.doubleclick.net"), MatchResult::Tracker);
    assert_eq!(blocklist_match("doubleclick.net"), MatchResult::Tracker);
}

#[test]
fn test_blocklist_case_insensitive() {
    assert_eq!(blocklist_match("GOOGLE-ANALYTICS.COM"), MatchResult::Tracker);
    assert_eq!(blocklist_match("Ad.DoubleClick.NET"), MatchResult::Tracker);
}

#[test]
fn test_blocklist_ip_malware() {
    assert_eq!(blocklist_match("192.0.2.66"), MatchResult::Malware);
}

#[test]
fn test_blocklist_clean_domain() {
    assert_eq!(blocklist_match("example.org"), MatchResult::Clean);
}
