use foxnetwarden::dnslog::{dns_status_from, is_invisible, parse_resolved_lines};

#[test]
fn test_parse_debug_query_line() {
    let text = "2026-11-18T13:52:24+03:00 CANINFEDORASI systemd-resolved[654]: Looking up RR for example.com IN A.\n";
    let events = parse_resolved_lines(text);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].domain, "example.com");
    assert_eq!(events[0].query_type, "A");
    assert!(events[0].timestamp.contains("13:52:24"));
}

#[test]
fn test_parse_multiple_queries_and_ignores_noise() {
    let text = concat!(
        "2026-11-18T13:52:24+03:00 H systemd-resolved[654]: Using degraded feature set UDP instead of UDP+EDNS0 for DNS server 192.168.1.1.\n",
        "2026-11-18T13:52:25+03:00 H systemd-resolved[654]: Looking up RR for tracker.example IN AAAA.\n",
        "2026-11-18T13:52:26+03:00 H systemd-resolved[654]: Looking up RR for ads.doubleclick.net IN A.\n",
        "2026-11-18T13:52:27+03:00 H systemd-resolved[654]: Sent message type=query\n",
    );
    let events = parse_resolved_lines(text);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].domain, "tracker.example");
    assert_eq!(events[0].query_type, "AAAA");
    assert_eq!(events[1].domain, "ads.doubleclick.net");
    assert_eq!(events[1].query_type, "A");
}

#[test]
fn test_invisible_when_disabled_or_no_queries() {
    // kapalıyken, sorgu olsa bile görünmez
    assert!(is_invisible(false, 1));
    // açık ama hiç sorgu yok (DoH / debug kapalı) -> görünmez
    assert!(is_invisible(true, 0));
    // açık ve sorgu var -> görünür
    assert!(!is_invisible(true, 1));
}

#[test]
fn test_dns_status_from_events() {
    let (enabled, visible) = dns_status_from(true, 3);
    assert!(enabled);
    assert!(visible);
    let (enabled, visible) = dns_status_from(false, 3);
    assert!(!enabled);
    assert!(!visible);
}
