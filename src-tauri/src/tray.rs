//! System tray icon + notifications + autostart desktop entry (Linux/XDG).
//! Notifications use notify-rust; autostart is a .desktop file under
//! ~/.config/autostart. All operations are best-effort and return a bool/string
//! so the Tauri command layer can surface state to the UI.

use std::fs;
use std::path::PathBuf;

const AUTOSTART_NAME: &str = "foxnetwarden.desktop";

fn autostart_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("autostart"))
}

fn autostart_path() -> Option<PathBuf> {
    autostart_dir().map(|d| d.join(AUTOSTART_NAME))
}

/// Whether the autostart desktop entry is currently installed.
pub fn autostart_enabled() -> bool {
    autostart_path().map(|p| p.exists()).unwrap_or(false)
}

fn desktop_entry(exec_path: &str) -> String {
    format!(
        "[Desktop Entry]\n\
Type=Application\n\
Name=FoxNetwarden\n\
Comment=Local-first personal firewall\n\
Exec={exec_path}\n\
Icon=foxnetwarden\n\
Terminal=false\n\
X-GNOME-Autostart-enabled=true\n"
    )
}

/// Install or remove the autostart entry. Returns the new enabled state.
pub fn autostart_toggle(exec_path: &str) -> Result<bool, String> {
    let dir = autostart_dir().ok_or_else(|| "config dizini bulunamadı".to_string())?;
    let path = dir.join(AUTOSTART_NAME);
    if path.exists() {
        fs::remove_file(&path).map_err(|e| e.to_string())?;
        Ok(false)
    } else {
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        fs::write(&path, desktop_entry(exec_path)).map_err(|e| e.to_string())?;
        Ok(true)
    }
}

/// Send a desktop notification. Best-effort: failures are swallowed and
/// reported as false so the caller can decide whether to surface them.
pub fn notify(title: &str, body: &str) -> bool {
    notify_rust::Notification::new()
        .summary(title)
        .body(body)
        .show()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_desktop_entry_contains_exec() {
        let e = desktop_entry("/usr/bin/foxnetwarden");
        assert!(e.contains("Exec=/usr/bin/foxnetwarden"));
        assert!(e.contains("Type=Application"));
        assert!(e.contains("X-GNOME-Autostart-enabled=true"));
    }
}
