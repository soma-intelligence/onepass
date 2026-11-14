// Every IPC command is declared here: Tauri then refuses any command a
// capability does not allow (capabilities/main.json), spec 2026-10-30 3.2.
const COMMANDS: &[&str] = &[
    "status",
    "create_account",
    "unlock",
    "lock",
    "vaults",
    "items",
    "item",
    "item_types",
    "new_item",
    "save_item",
    "trash_item",
    "set_favorite",
    "reveal_field",
    "copy_field",
    "totp",
    "generate_password",
    "watchtower",
    "set_archived",
    "restore_item",
    "delete_item",
    "move_item",
    "duplicate_item",
    "password_history",
    "history_value",
    "save_vault",
    "delete_vault",
    "change_password",
    "account",
    "set_profile_name",
    "strength",
    "copy_secret",
    "open_url",
    "add_attachment",
    "remove_attachment",
    "open_attachment",
    "export_attachment",
    "hello_status",
    "enable_hello",
    "disable_hello",
    "unlock_with_hello",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri build");
}
