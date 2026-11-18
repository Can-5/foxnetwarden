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
    assert!(conf.contains("Security"), "bundle category must be Security");
}

#[test]
fn test_capabilities_default_exists() {
    let cap = crate_root().join("capabilities/default.json");
    assert!(cap.exists(), "capabilities/default.json must exist for Tauri IPC");
    let content = fs::read_to_string(cap).unwrap();
    assert!(content.contains("core:default"), "must grant core:default");
}
