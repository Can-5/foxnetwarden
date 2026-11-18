use foxnetwarden::analyzer::{analyzer_score, analyzer_score_with_targets};
use foxnetwarden::collector::Connection;

fn conn_to(remote: &str) -> Connection {
    Connection {
        pid: Some(1234),
        name: "firefox".to_string(),
        local: "192.168.1.103:54321".to_string(),
        remote: remote.to_string(),
        state: "ESTAB".to_string(),
        duration: 0,
    }
}

#[test]
fn test_analyzer_score_known_tracker() {
    let c = conn_to("google-analytics.com:443");
    assert!(analyzer_score(&c) >= 60, "tracker should score high");
}

#[test]
fn test_analyzer_score_malware_ip() {
    let c = conn_to("192.0.2.66:4444");
    assert!(analyzer_score(&c) >= 90, "malware IP should score very high");
}

#[test]
fn test_analyzer_score_clean_domain() {
    let c = conn_to("example.org:443");
    assert_eq!(analyzer_score(&c), 0, "clean domain should score zero");
}

#[test]
fn test_analyzer_score_top_talker() {
    let c = conn_to("example.org:443");
    let low = analyzer_score_with_targets(&c, 2);
    let high = analyzer_score_with_targets(&c, 25);
    assert!(high > low, "more distinct targets must raise the score");
    assert!(high >= 30, "top-talker threshold should add weight");
}
