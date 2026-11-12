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
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri build");
}
