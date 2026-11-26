import SwiftUI
import VaultKit

/// Keyboard commands, identical on Mac and iPad (spec 6.1, 6.3): ⌘N new item, ⌘⇧I import, ⌘E edit, ⌘S save,
/// ⌘F search, ⌘L lock, ⌘⌫ move to Supprimés récemment, ⌘C copy the password, ⌘⇧C copy the
/// verification code. The views on screen act on the requests
/// (`AppModel.editRequest`, `saveRequest`, `searchFocusRequest`). ⌘⌫ is enabled only while the
/// item list has keyboard focus (`FocusedValues.itemListFocused`): never from a text field.
struct BrowseCommands: Commands {
    let model: AppModel
    @FocusedValue(\.itemListFocused) private var listFocused
    @FocusedValue(\.mainWindowFocused) private var mainWindowFocused

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
            #if os(macOS)
            // ⌘C copies the selected item's password only when no text has the keyboard: Édition >
            // Copier comes first in the menu bar and takes ⌘C in a text field; should this item get it
            // anyway, the text copy is passed on (`copyPasswordOrText`).
            Button("copy.command.password") { copyPasswordOrText() }
                .keyboardShortcut("c", modifiers: .command)
                .disabled(!canCopy)
            Button("copy.command.code") { Task { await model.copyFromSelection(.verificationCode) } }
                .keyboardShortcut("c", modifiers: [.command, .shift])
                .disabled(!canCopy)
            Divider()
            #endif
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
            Button("Verrouiller OnePass") {
                #if os(macOS)
                // Never silent: unsaved changes bring the window and its confirmation forward.
                model.lockFromMenuBar()
                #else
                model.perform(.lock)
                #endif
            }
                .keyboardShortcut("l", modifiers: .command)
                .disabled(model.session.state != .unlocked)
        }
    }

    #if os(macOS)
    /// ⌘C / ⌘⇧C: the item list with an item shown, in the main window (never from Réglages or an
    /// item window).
    private var canCopy: Bool {
        unlocked && mainWindowFocused == true && model.canCopyFromSelection
    }

    /// A text field or text view holding the keyboard keeps ⌘C for its own selection.
    private func copyPasswordOrText() {
        if NSApp.keyWindow?.firstResponder is NSText {
            NSApp.sendAction(#selector(NSText.copy(_:)), to: nil, from: nil)
            return
        }
        Task { await model.copyFromSelection(.password) }
    }
    #endif
}

extension FocusedValues {
    /// True while the item list (not a text field) has keyboard focus.
    @Entry var itemListFocused: Bool?
    /// True while the main window (not Réglages or an item window) is the focused scene.
    @Entry var mainWindowFocused: Bool?
}
