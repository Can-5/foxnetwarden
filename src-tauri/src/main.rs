#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .build(tauri::generate_context!())
        .expect("error while running tauri application");
}
