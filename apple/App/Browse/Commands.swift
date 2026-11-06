import SwiftUI
import VaultKit

/// Keyboard commands, identical on Mac and iPad (spec 6.1, 6.3): ⌘N new item, ⌘⇧I import, ⌘E edit, ⌘S save,
/// ⌘F search, ⌘L lock, ⌘⌫ move to Supprimés récemment. The views on screen act on the requests
/// (`AppModel.editRequest`, `saveRequest`, `searchFocusRequest`). ⌘⌫ is enabled only while the
/// item list has keyboard focus (`FocusedValues.itemListFocused`): never from a text field.
struct BrowseCommands: Commands {
    let model: AppModel
    @FocusedValue(\.itemListFocused) private var listFocused

    private var unlocked: Bool { model.session.state == .unlocked && !model.onboardingInProgress }

    var body: some Commands {
        // Replaces "New Window": one window in milestone 2.
        CommandGroup(replacing: .newItem) {
            Button("Nouvel élément") { model.showNewItemPicker = true }
                .keyboardShortcut("n", modifiers: .command)
                .disabled(!unlocked)
            Divider()
            Button("Importer…") { model.showImport = true }
                .keyboardShortcut("i", modifiers: [.command, .shift])
                .disabled(!unlocked)
            Button("browse.restoreBackup") { model.showRestore = true }
                .disabled(!unlocked)
            #if os(macOS)
            Divider()
            // The Mac shows a code (QR and typed); the new iPhone or iPad scans or types it.
            Button("Configurer un appareil…") { model.showHostDevice = true }
                .disabled(!unlocked)
            #endif
        }
        // Replaces the standard Find submenu, whose ⌘F would compete with this one.
        CommandGroup(replacing: .textEditing) {
            Button("common.search") { model.searchFocusRequest &+= 1 }
                .keyboardShortcut("f", modifiers: .command)
                .disabled(!unlocked)
        }
        CommandMenu("Élément") {
            Button("common.edit") { model.editRequest &+= 1 }
                .keyboardShortcut("e", modifiers: .command)
                .disabled(!unlocked || model.selectedItem == nil || model.isEditing)
            Button("Enregistrer") { model.saveRequest &+= 1 }
                .keyboardShortcut("s", modifiers: .command)
                .disabled(!unlocked || !model.isEditing)
            Divider()
            Button("browse.moveToTrash") { model.trashSelection() }
                .keyboardShortcut(.delete, modifiers: .command)
                .disabled(!unlocked || listFocused != true || !model.canTrashSelection)
        }
        CommandGroup(after: .appSettings) {
            Button("Verrouiller OnePass") { model.perform(.lock) }
                .keyboardShortcut("l", modifiers: .command)
                .disabled(model.session.state != .unlocked)
        }
    }
}

extension FocusedValues {
    /// True while the item list (not a text field) has keyboard focus.
    @Entry var itemListFocused: Bool?
}
