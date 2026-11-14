//! OnePass for Windows (and later Linux): Tauri 2, milestone X2 of spec
//! 2026-10-30. The backend links the core directly; the web view gets typed
//! commands only (each one declared in build.rs and allowed in
//! capabilities/main.json) and never a key or a blob.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod breach;
mod commands;
mod device;
mod dialog;
mod hello;
mod prefs;
mod secrets;
mod shell;
mod state;
mod view;

use std::time::Duration;

use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let mut dir = app
                .path()
                .app_local_data_dir()
                .map_err(|e| format!("no data directory: {e}"))?;
            // Debug builds only: the end-to-end tests run on a throwaway
            // vault, never on the user's.
            #[cfg(debug_assertions)]
            if let Some(d) = std::env::var_os("ONEPASS_DATA_DIR") {
                dir = d.into();
            }
            std::fs::create_dir_all(&dir)?;
            state::purge_opened();
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
            commands::watchtower,
            commands::set_archived,
            commands::restore_item,
            commands::delete_item,
            commands::move_item,
            commands::duplicate_item,
            commands::password_history,
            commands::history_value,
            commands::save_vault,
            commands::delete_vault,
            commands::change_password,
            commands::account,
            commands::set_profile_name,
            commands::strength,
            commands::copy_secret,
            commands::open_url,
            commands::add_attachment,
            commands::remove_attachment,
            commands::open_attachment,
            commands::export_attachment,
            commands::hello_status,
            commands::enable_hello,
            commands::disable_hello,
            commands::unlock_with_hello,
            commands::save_pending,
            commands::discard_pending,
            commands::export_backup,
            commands::export_csv,
            commands::pick_backup,
            commands::pending_archive,
            commands::preview_restore,
            commands::restore_backup,
            commands::forget_file,
            commands::pick_import,
            commands::preview_import,
            commands::import_items,
            commands::set_check_breaches,
        ])
        .run(tauri::generate_context!())
        .expect("OnePass failed to start");
}
