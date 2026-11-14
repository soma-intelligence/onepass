//! OnePass for Windows (and later Linux): Tauri 2, milestone X2 of spec
//! 2026-10-30. The backend links the core directly; the web view gets typed
//! commands only (each one declared in build.rs and allowed in
//! capabilities/main.json) and never a key or a blob.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod device;
mod secrets;
mod state;
mod view;

use std::time::Duration;

use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = app
                .path()
                .app_local_data_dir()
                .map_err(|e| format!("no data directory: {e}"))?;
            std::fs::create_dir_all(&dir)?;
            let state = state::AppState::new(dir)?;
            app.manage(state);
            if let Some(window) = app.get_webview_window("main") {
                // Like FLAG_SECURE on Android: the window stays out of
                // screenshots and screen sharing (WDA_EXCLUDEFROMCAPTURE).
                let _ = window.set_content_protected(true);
            }
            // Auto-lock after inactivity, checked twice a minute.
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(30));
                    let state = handle.state::<state::AppState>();
                    if state.lock_if_idle() {
                        let _ = tauri::Emitter::emit(&handle, "locked", ());
                    }
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                window.state::<state::AppState>().lock();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::create_account,
            commands::unlock,
            commands::lock,
            commands::vaults,
            commands::items,
            commands::item,
            commands::item_types,
            commands::new_item,
            commands::save_item,
            commands::trash_item,
            commands::set_favorite,
            commands::reveal_field,
            commands::copy_field,
            commands::totp,
            commands::generate_password,
        ])
        .run(tauri::generate_context!())
        .expect("OnePass failed to start");
}
