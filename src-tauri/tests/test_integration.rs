//! End-to-end smoke: collector -> db -> analyzer -> blocklist -> firewall chain.
//! Root-required privileged nft writes are #[ignore]d and can be run explicitly
//! with `cargo test -- --ignored` on a host where pkexec/nft are available.

use foxnetwarden::analyzer::analyzer_score_with_targets;
use foxnetwarden::blocklist::{blocklist_match, MatchResult};
use foxnetwarden::collector::Connection;
use foxnetwarden::db::{
    db_insert_conn, history_query_conn, init_db_conn, top_talkers_conn,
};
use foxnetwarden::firewall::{
    killswitch_set, nft_killswitch_script, nft_rule_add, rule_add, validate_target, Action, Target,
};

fn conn(pid: Option<u32>, name: &str, remote: &str) -> Connection {
    Connection {
        pid,
        name: name.to_string(),
        local: "192.168.1.103:50000".to_string(),
        remote: remote.to_string(),
        state: "ESTAB".to_string(),
        duration: 0,
    }
}

/// Pure (non-privileged) chain: observe -> persist -> query -> score -> flag.
#[test]
fn test_observe_to_analysis_chain() {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    init_db_conn(&db).unwrap();

    // collector-produced connections
    let c1 = conn(Some(100), "firefox", "doubleclick.net:443"); // tracker
    let c2 = conn(Some(101), "curl", "api.github.com:443"); // clean
    let c3 = conn(None, "?", "192.0.2.66:443"); // malware IP, other uid

    db_insert_conn(&db, &c1).unwrap();
    db_insert_conn(&db, &c2).unwrap();
    db_insert_conn(&db, &c3).unwrap();

    // history + top talkers from the persisted data
    let history = history_query_conn(&db).unwrap();
    assert_eq!(history.len(), 3, "all observed connections persisted");
    let talkers = top_talkers_conn(&db).unwrap();
    assert!(!talkers.is_empty());

    // analyzer + blocklist agree on which connections are suspicious
    let s_tracker = analyzer_score_with_targets(&c1, 3);
    let s_clean = analyzer_score_with_targets(&c2, 3);
    let s_malware = analyzer_score_with_targets(&c3, 3);
    assert!(s_tracker > s_clean, "tracker scores above clean");
    assert!(s_malware > s_clean, "malware IP scores above clean");
    assert!(s_clean < 30, "clean connection stays low");

    assert!(matches!(blocklist_match("doubleclick.net"), MatchResult::Tracker));
    assert!(matches!(blocklist_match("192.0.2.66"), MatchResult::Malware));
    assert!(matches!(blocklist_match("api.github.com"), MatchResult::Clean));
}

/// The nft rule text the privileged layer would feed to `pkexec nft -f -`.
#[test]
fn test_firewall_rule_generation_chain() {
    let target = validate_target("192.0.2.66").unwrap();
    assert!(matches!(target, Target::Cidr(_)));
    let rule = nft_rule_add(&target, Action::Block);
    assert!(rule.contains("inet foxnetwarden"), "rule targets our table");
    assert!(rule.contains("drop"), "block action uses drop");

    let domain = validate_target("tracker.example.com").unwrap();
    assert!(matches!(domain, Target::Domain(_)));
    let domain_rule = nft_rule_add(&domain, Action::Block);
    // Domain set names normalize dots to underscores (firewall::set_name).
    assert!(domain_rule.contains("@tracker_example_com_set"), "{domain_rule}");

    // Kill switch script covers everything, no bypass exceptions.
    let on = nft_killswitch_script(true);
    assert!(on.contains("policy drop"));
    assert!(!on.contains("accept"));
    let off = nft_killswitch_script(false);
    assert!(off.contains("delete"));
}

/// Privileged: actually write rules via pkexec. Requires root / pkexec auth.
#[test]
#[ignore = "requires root + pkexec authentication"]
fn test_privileged_rule_add_and_killswitch_revert() {
    let target = validate_target("192.0.2.123").unwrap();
    rule_add("192.0.2.123", Action::Block).expect("pkexec block rule");
    killswitch_set(true).expect("kill switch on");
    killswitch_set(false).expect("kill switch off / revert");
    let _ = target;
}
