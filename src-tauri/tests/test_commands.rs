use std::fs;
use std::path::PathBuf;

/// The Tauri command names exposed to the frontend (spec Task 5 Interface list).
const REQUIRED_COMMANDS: &[&str] = &[
    "fw_status",
    "live_connections",
    "history_query",
    "rule_add",
    "rule_remove",
    "killswitch_set",
    "blocklist_stats",
    "top_talkers",
    "dns_mode",
    "dns_status",
    "dns_mode_set",
    "dns_events",
    "tray_toggle_autostart",
];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn test_required_command_names_are_registered_in_main() {
    let main_src = fs::read_to_string(crate_root().join("src/main.rs"))
        .expect("main.rs must exist");
    // Generate_handler! lists the commands; every required name must appear there.
    for name in REQUIRED_COMMANDS {
        assert!(
            main_src.contains(name),
            "command {name} must be registered in main.rs"
        );
    }
}

#[test]
fn test_tauri_conf_identifier_and_window() {
    let conf = fs::read_to_string(crate_root().join("tauri.conf.json"))
        .expect("tauri.conf.json must exist");
    assert!(conf.contains("app.foxnetwarden.firewall"), "identifier mismatch");
    assert!(conf.contains("1280"), "window width must be 1280");
    assert!(conf.contains("960"), "window minWidth must be 960");
    assert!(conf.contains("#14100e"), "window background must be #14100e");
    assert!(conf.contains("Utility"), "bundle category must be Utility");
    assert!(
        conf.contains("withGlobalTauri"),
        "C2: withGlobalTauri must be true so packaged app exposes window.__TAURI__"
    );
}

// I2/I3/I4/M3: production wiring that a packaged app must have.
#[test]
fn test_main_wires_tray_persistence_and_dns_split() {
    let main_src = fs::read_to_string(crate_root().join("src/main.rs")).unwrap();
    assert!(main_src.contains("on_window_event"), "I2: keep tray alive on window close");
    assert!(main_src.contains("prevent_close"), "I2: prevent_close on CloseRequested");
    assert!(main_src.contains("thread::spawn"), "I2/I3: background collector loop");
    assert!(main_src.contains("db_insert"), "I3: persist observations to history");
    assert!(main_src.contains("analyzer_score"), "I2: score connections in background");
    assert!(main_src.contains("domainblock_sync"), "I1: sync domain sets periodically");
    assert!(main_src.contains("killswitch_set(false)"), "M3: revert kill switch on quit");
    // I4: dns_mode(None) must NOT toggle; the read path is a separate command.
    // M-2: the real signature is `fn dns_mode`, not `async fn dns_mode`.
    // The old split made this vacuous (nth(1)=None -> ""). Pin a non-empty body.
    let dns_fn = main_src
        .split("fn dns_mode(enabled: Option<bool>)")
        .nth(1)
        .map(|s| s.chars().take(400).collect::<String>())
        .unwrap_or_default();
    assert!(
        !dns_fn.is_empty(),
        "M-2: dns_mode body must be found so the toggle assertion is not vacuous"
    );
    assert!(
        !dns_fn.contains("dns_mode_toggle"),
        "I4: dns_mode(None) must not toggle opt-in silently"
    );
}

#[test]
fn test_final_review_fixes_wired() {
    let main_src = fs::read_to_string(crate_root().join("src/main.rs")).unwrap();

    // I-2: dns_events command must be registered and actually return events.
    assert!(main_src.contains("dns_events,"), "I-2: dns_events must be in generate_handler!");

    // I-5: tray kill-switch menu item must toggle state, not just notify.
    assert!(
        main_src.contains("KILLSWITCH_TOGGLE"),
        "I-5: tray kill-switch menu must call killswitch_set on state"
    );

    // I-1: background observer must NOT run interactive pkexec every poll.
    // We gate domain re-resolution behind an explicit domain-rule flag instead.
    assert!(
        main_src.contains("DOMAIN_RULES_ACTIVE"),
        "I-1: domain set re-resolution must be gated (no pkexec every 30s)"
    );
}

#[test]
fn test_capabilities_default_exists() {
    let cap = crate_root().join("capabilities/default.json");
    assert!(cap.exists(), "capabilities/default.json must exist for Tauri IPC");
    let content = fs::read_to_string(cap).unwrap();
    assert!(content.contains("core:default"), "must grant core:default");
}
