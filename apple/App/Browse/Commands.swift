import SwiftUI
import VaultKit

/// Keyboard commands, identical on Mac and iPad (spec 6.1, 6.3): ⌘N new item, ⌘E edit, ⌘S save,
/// ⌘⌫ move to Supprimés récemment, ⌘F search, ⌘L lock. The views on screen act on the requests
/// (`AppModel.editRequest`, `saveRequest`, `searchFocusRequest`). ⌥⌘N opens another window.
struct BrowseCommands: Commands {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    private var unlocked: Bool { model.session.state == .unlocked && !model.onboardingInProgress }

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("Nouvel élément") { model.showNewItemPicker = true }
                .keyboardShortcut("n", modifiers: .command)
                .disabled(!unlocked)
            Button("Nouvelle fenêtre") { openWindow(id: OnePassApp.mainWindowID) }
                .keyboardShortcut("n", modifiers: [.command, .option])
        }
        CommandGroup(after: .textEditing) {
            Button("Rechercher") { model.searchFocusRequest &+= 1 }
                .keyboardShortcut("f", modifiers: .command)
                .disabled(!unlocked)
        }
        CommandMenu("Élément") {
            Button("Modifier") { model.editRequest &+= 1 }
                .keyboardShortcut("e", modifiers: .command)
                .disabled(!unlocked || model.selectedItem == nil || model.isEditing)
            Button("Enregistrer") { model.saveRequest &+= 1 }
                .keyboardShortcut("s", modifiers: .command)
                .disabled(!unlocked || !model.isEditing)
            Divider()
            Button("Mettre à la corbeille") { model.trashSelection() }
                .keyboardShortcut(.delete, modifiers: .command)
                .disabled(!unlocked || !model.canTrashSelection)
        }
        CommandGroup(after: .appSettings) {
            Button("Verrouiller OnePass") { model.perform(.lock) }
                .keyboardShortcut("l", modifiers: .command)
                .disabled(model.session.state != .unlocked)
        }
    }
}
