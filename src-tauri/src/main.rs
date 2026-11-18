#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::{Manager, WindowEvent};
use std::sync::atomic::{AtomicBool, Ordering};

// I-1: domain-set re-resolution (which needs interactive pkexec) only runs when
// a domain-blocking rule is actually active. Default off => no password dialog
// every 30 s in pure observation mode.
static DOMAIN_RULES_ACTIVE: AtomicBool = AtomicBool::new(false);
// I-5: tray menu id + desired-state flag so the menu item really toggles.
const KILLSWITCH_TOGGLE: &str = "killswitch";
static KILLSWITCH_ON: AtomicBool = AtomicBool::new(false);

// ---- Command layer: thin wrappers around the pure/testable core modules. ----
// Every command maps library errors to String so the webview gets a clean
// {ok:false, error} shape; privileged commands go through pkexec in Rust.

#[tauri::command]
fn fw_status() -> Result<String, String> {
    foxnetwarden::firewall::fw_status().map_err(|e| e.to_string())
}

#[tauri::command]
fn live_connections() -> Result<Vec<foxnetwarden::Connection>, String> {
    foxnetwarden::live_connections()
}

#[tauri::command]
fn history_query() -> Result<Vec<foxnetwarden::HistoryRow>, String> {
    foxnetwarden::history_query()
}

#[tauri::command]
fn rule_add(target: String, action: String) -> Result<(), String> {
    let action = match action.as_str() {
        "block" => foxnetwarden::firewall::Action::Block,
        "allow" => foxnetwarden::firewall::Action::Allow,
        other => return Err(format!("geçersiz eylem: {other}")),
    };
    foxnetwarden::firewall::rule_add(&target, action).map_err(|e| e.to_string())
}

#[tauri::command]
fn rule_remove(id: String) -> Result<(), String> {
    foxnetwarden::firewall::rule_remove(&id).map_err(|e| e.to_string())
}

#[tauri::command]
fn killswitch_set(active: bool) -> Result<(), String> {
    let result = foxnetwarden::firewall::killswitch_set(active).map_err(|e| e.to_string());
    if result.is_ok() {
        KILLSWITCH_ON.store(active, Ordering::Relaxed);
        let msg = if active {
            "Kill Switch AÇIK — tüm ağ trafiği kesildi"
        } else {
            "Kill Switch KAPALI — ağ trafiği serbest"
        };
        foxnetwarden::tray::notify("FoxNetwarden", msg);
    }
    result
}

#[tauri::command]
fn blocklist_stats() -> (usize, usize, usize) {
    foxnetwarden::blocklist_stats()
}

#[tauri::command]
fn top_talkers() -> Result<Vec<foxnetwarden::Talker>, String> {
    foxnetwarden::top_talkers()
}

// I4: three distinct commands with distinct intents. A read never mutates state;
// a write always carries an explicit boolean. The old single dns_mode(None)
// toggled on read, which silently flipped the opt-in when the UI polled status.
#[tauri::command]
fn dns_status() -> foxnetwarden::DnsStatus {
    foxnetwarden::dns_status()
}

#[tauri::command]
fn dns_mode_set(enabled: bool) -> foxnetwarden::DnsStatus {
    foxnetwarden::dns_mode_set(enabled);
    foxnetwarden::dns_status()
}

#[tauri::command]
fn dns_mode(enabled: Option<bool>) -> foxnetwarden::DnsStatus {
    if let Some(value) = enabled {
        foxnetwarden::dns_mode_set(value);
    }
    // None is a pure read — no mutation, no toggle.
    foxnetwarden::dns_status()
}

// I-2: expose journal-parsed DNS events to the UI (honest empty when invisible).
#[tauri::command]
fn dns_events() -> Vec<foxnetwarden::DnsEvent> {
    foxnetwarden::dns_events()
}

#[tauri::command]
fn tray_toggle_autostart() -> Result<bool, String> {
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "foxnetwarden".to_string());
    foxnetwarden::tray::autostart_toggle(&exe)
}

// I2/I3: background observation loop. Persists every observation to SQLite and
// scores it with the same analyzer the UI uses; high-scoring connections raise a
// desktop notification. Runs off the UI thread so history/analysis are populated
// even when no browser screen is open.
fn spawn_observation_loop() {
    std::thread::spawn(|| loop {
        if let Ok(conns) = foxnetwarden::live_connections() {
            let mut high = 0u32;
            for c in &conns {
                let _ = foxnetwarden::db_insert(c);
                if foxnetwarden::analyzer_score(c) >= 60 {
                    high += 1;
                }
            }
            if high > 0 {
                foxnetwarden::tray::notify(
                    "FoxNetwarden",
                    &format!("{high} şüpheli bağlantı tespit edildi"),
                );
            }
        }
        // I-1: only re-resolve domains when a domain-blocking rule is active.
        // Otherwise skip entirely — no interactive pkexec dialog every 30 s.
        if DOMAIN_RULES_ACTIVE.load(Ordering::Relaxed) {
            let trackers: Vec<String> = vec![
                "doubleclick.net".into(),
                "google-analytics.com".into(),
            ];
            let _ = foxnetwarden::domainblock_sync(&trackers);
        }
        std::thread::sleep(std::time::Duration::from_secs(30));
    });
}

fn build_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;

    let show = MenuItem::with_id(app, "show", "Pencereyi göster", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, KILLSWITCH_TOGGLE, "Kill Switch aç/kapat", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Çık", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &toggle, &quit])?;

    let icon = app
        .default_window_icon()
        .cloned()
        .ok_or("varsayılan pencere ikonu yok")?;

    TrayIconBuilder::new()
        .icon(icon)
        .menu(&menu)
        .tooltip("FoxNetwarden")
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            KILLSWITCH_TOGGLE => {
                // I-5: the tray item really toggles the kill switch, keeping the
                // desired state in sync with the window UI.
                let next = !KILLSWITCH_ON.load(Ordering::Relaxed);
                match foxnetwarden::firewall::killswitch_set(next) {
                    Ok(()) => {
                        KILLSWITCH_ON.store(next, Ordering::Relaxed);
                        let msg = if next {
                            "Kill Switch AÇIK — tüm ağ kesildi"
                        } else {
                            "Kill Switch KAPALI — ağ serbest"
                        };
                        foxnetwarden::tray::notify("FoxNetwarden", msg);
                    }
                    Err(e) => {
                        foxnetwarden::tray::notify("FoxNetwarden", &format!("Kill Switch hatası: {e}"));
                    }
                }
            }
            "quit" => {
                // M3: never leave the machine cut off when the app is closed.
                let _ = foxnetwarden::firewall::killswitch_set(false);
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                if let Some(w) = tray.app_handle().get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
        })
        .build(app)?;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            fw_status,
            live_connections,
            history_query,
            rule_add,
            rule_remove,
            killswitch_set,
            blocklist_stats,
            top_talkers,
            dns_status,
            dns_mode_set,
            dns_mode,
            dns_events,
            tray_toggle_autostart
        ])
        .on_window_event(|window, event| {
            // I2: closing the window hides it to the tray instead of killing the
            // app — the tray (and its kill-switch revert on quit) stays alive.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            if let Err(e) = build_tray(app) {
                eprintln!("tray kurulamadı: {e}");
            }
            spawn_observation_loop();
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
