//! OnePass for Windows (and later Linux): Tauri 2, milestone X2 of spec
//! 2026-10-30. The backend links the core directly; the web view gets typed
//! commands only (each one declared in build.rs and allowed in
//! capabilities/main.json) and never a key or a blob.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod breach;
mod commands;
mod contacts;
mod device;
mod dialog;
mod hello;
mod iconpack;
mod pairing;
mod prefs;
mod secrets;
mod sharing_cmds;
mod shell;
mod state;
mod sync;
mod sync_cmds;
#[cfg(all(debug_assertions, feature = "test-mailbox"))]
mod testmailbox;
mod view;
mod zones;

use std::time::Duration;

use tauri::Manager;

/// Every command that writes to the store is followed by a sync round
/// (debounced, sync.rs), wherever the UI calls it from.
fn after_writes<F>(handler: F) -> impl Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static
where
    F: Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static,
{
    move |invoke| {
        let command = invoke.message.command().to_owned();
        let app = invoke.message.webview().app_handle().clone();
        let handled = handler(invoke);
        if sync::WRITES.contains(&command.as_str()) {
            app.state::<state::AppState>().sync.changed();
        }
        handled
    }
}

/// Debug builds with `test-mailbox` and ONEPASS_TEST_MAILBOX=1: the test
/// mailbox runs in this process and stands for the OnePass server. Its port
/// is ONEPASS_TEST_MAILBOX_PORT (else any free one); its URL and the path of
/// its CA (written next to the vault) are printed.
#[cfg(all(debug_assertions, feature = "test-mailbox"))]
fn start_test_mailbox(dir: &std::path::Path) {
    if std::env::var("ONEPASS_TEST_MAILBOX").as_deref() != Ok("1") {
        return;
    }
    let port = std::env::var("ONEPASS_TEST_MAILBOX_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    match testmailbox::start(port) {
        Ok(base) => {
            let ca = dir.join("test-mailbox-ca.pem");
            let _ = std::fs::write(&ca, testmailbox::CA_PEM);
            println!("test mailbox: {base}");
            println!("test mailbox CA: {}", ca.display());
            sync::set_debug_hosted(sync::Server {
                base_url: base,
                ca_pem: Some(testmailbox::CA_PEM.into()),
            });
        }
        Err(e) => eprintln!("test mailbox: {e}"),
    }
}

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
            let state = state::AppState::new(dir.clone())?;
            app.manage(state);
            #[cfg(all(debug_assertions, feature = "test-mailbox"))]
            start_test_mailbox(&dir);
            sync::spawn(app.handle().clone());
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
        .invoke_handler(after_writes(tauri::generate_handler![
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
            commands::item_timeline,
            commands::travel_status,
            commands::set_vault_travel_safe,
            commands::enter_travel,
            commands::exit_travel,
            commands::duplicate_groups,
            commands::merge_duplicates,
            commands::merge_sure_duplicates,
            commands::resolve_duplicates,
            commands::wifi_qr,
            commands::site_icons,
            commands::icon_image,
            commands::set_site_icons,
            sync_cmds::sync_status,
            sync_cmds::sync_now,
            sync_cmds::check_server,
            sync_cmds::enable_sync,
            sync_cmds::restore_kit,
            sync_cmds::rename_device,
            sync_cmds::revoke_device,
            sync_cmds::pair_state,
            sync_cmds::pair_host_start,
            sync_cmds::pair_host_approve,
            sync_cmds::pair_join_start,
            sync_cmds::pair_join_confirm,
            sync_cmds::pair_join_password,
            sync_cmds::pair_cancel,
            sync_cmds::read_kit_image,
            sync_cmds::kit_devices,
            sync_cmds::answer_kit_device,
            sync_cmds::claim_only_device,
            sharing_cmds::sharing_state,
            sharing_cmds::recovery_alerts,
            sharing_cmds::cancel_recovery,
            sharing_cmds::contact_invite_create,
            sharing_cmds::contact_invite_open,
            sharing_cmds::contact_invite_state,
            sharing_cmds::contact_invite_cancel,
            sharing_cmds::rename_contact,
            sharing_cmds::remove_contact,
            sharing_cmds::confirm_safety_number,
            sharing_cmds::add_vault_member,
            sharing_cmds::set_member_role,
            sharing_cmds::remove_member,
            sharing_cmds::leave_shared_vault,
            sharing_cmds::stop_sharing,
            sharing_cmds::accept_share_invite,
            sharing_cmds::decline_share_invite,
            sharing_cmds::adopt_member_identity,
            sharing_cmds::send_item,
            sharing_cmds::accept_received_item,
            sharing_cmds::decline_received_item,
            sharing_cmds::create_family,
            sharing_cmds::invite_to_family,
            sharing_cmds::accept_family_invite,
            sharing_cmds::remove_from_family,
            sharing_cmds::leave_family,
            sharing_cmds::set_family_role,
            sharing_cmds::add_family_vault,
            sharing_cmds::enroll_recovery,
            sharing_cmds::disable_recovery,
            sharing_cmds::request_recovery,
            sharing_cmds::recovery_status,
        ]))
        .run(tauri::generate_context!())
        .expect("OnePass failed to start");
}
