use foxnetwarden::firewall::{
    nft_killswitch_script, nft_rule_add, nft_rule_remove, pkexec_nft_args, resolve_pkexec,
    validate_target, Action, FirewallError, Target,
};

#[test]
fn test_validate_target_accepts_cidr_domain_port() {
    assert!(matches!(validate_target("192.0.2.0/24"), Ok(Target::Cidr(_))));
    assert!(matches!(validate_target("2001:db8::/32"), Ok(Target::Cidr(_))));
    assert!(matches!(validate_target("example.com"), Ok(Target::Domain(_))));
    assert!(matches!(validate_target("443"), Ok(Target::Port(443))));
}

#[test]
fn test_validate_target_rejects_free_form_nft_injection() {
    assert!(validate_target("192.0.2.0/24; drop all").is_err());
    assert!(validate_target("add rule inet filter input drop").is_err());
    assert!(validate_target("example.com && nft").is_err());
    assert!(validate_target("$(whoami)").is_err());
    assert!(validate_target("").is_err());
}

#[test]
fn test_nft_rule_add_block_and_allow() {
    let cidr = validate_target("192.0.2.0/24").unwrap();
    let block = nft_rule_add(&cidr, Action::Block);
    assert!(block.contains("inet foxnetwarden block"), "{block}");
    assert!(block.contains("ip daddr 192.0.2.0/24 drop"), "{block}");

    let allow = nft_rule_add(&cidr, Action::Allow);
    assert!(allow.contains("ip daddr 192.0.2.0/24 accept"), "{allow}");
}

#[test]
fn test_nft_rule_remove_rejects_non_numeric_handle() {
    assert!(nft_rule_remove("7")
        .unwrap()
        .contains("delete rule inet foxnetwarden block handle 7"));
    assert!(matches!(
        nft_rule_remove("7; drop"),
        Err(FirewallError::InvalidTarget(_))
    ));
}

#[test]
fn test_nft_killswitch_drops_everything_and_leaves_no_bypass() {
    let on = nft_killswitch_script(true);
    assert!(on.contains("table inet foxnetwarden"), "{on}");
    assert!(on.contains("hook output"), "{on}");
    assert!(on.contains("policy drop"), "{on}");
    // priority must be negative so allow rules cannot punch through
    assert!(on.contains("priority -"), "{on}");
    // no established/loopback/DNS exception
    assert!(!on.contains("established"), "{on}");
    assert!(!on.contains("lo accept"), "{on}");

    let off = nft_killswitch_script(false);
    assert!(off.contains("delete chain inet foxnetwarden killswitch"), "{off}");
}

#[test]
fn test_pkexec_command_shape() {
    let args = pkexec_nft_args();
    assert_eq!(args.first().map(String::as_str), Some("pkexec"));
    assert!(args.iter().any(|a| a == "nft"));
    assert!(args.iter().any(|a| a == "-f"));
}

#[test]
fn test_resolve_pkexec_missing_is_error() {
    match resolve_pkexec("/definitely/not/a/real/pkexec") {
        Err(FirewallError::PkexecMissing) => {}
        other => panic!("expected PkexecMissing, got {other:?}"),
    }
    assert!(resolve_pkexec("/usr/bin/pkexec").is_ok());
}
