#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::Manager;

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

#[tauri::command]
fn dns_mode(enabled: Option<bool>) -> foxnetwarden::DnsStatus {
    if let Some(value) = enabled {
        foxnetwarden::dns_mode_set(value);
    } else {
        foxnetwarden::dns_mode_toggle();
    }
    foxnetwarden::dns_status()
}

#[tauri::command]
fn tray_toggle_autostart() -> Result<bool, String> {
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "foxnetwarden".to_string());
    foxnetwarden::tray::autostart_toggle(&exe)
}

fn build_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;

    let show = MenuItem::with_id(app, "show", "Pencereyi göster", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "killswitch", "Kill Switch aç/kapat", true, None::<&str>)?;
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
            "killswitch" => {
                // Toggle is driven by the UI command so state stays in one place;
                // tray merely notifies that the user requested it.
                foxnetwarden::tray::notify("FoxNetwarden", "Kill Switch isteği alındı — pencereden durumu görün");
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                }
            }
            "quit" => app.exit(0),
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
            dns_mode,
            tray_toggle_autostart
        ])
        .setup(|app| {
            if let Err(e) = build_tray(app) {
                eprintln!("tray kurulamadı: {e}");
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
