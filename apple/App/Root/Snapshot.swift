#if DEBUG && os(macOS)
import AppKit
import SwiftUI
import VaultKit

/// `-OnePassSnapshot <folder>` (Debug, Mac): with the demo data, renders the app's own window
/// (frame and toolbar included) into PNGs at 1280 x 820, light then dark, then quits. Uses
/// `cacheDisplay`, so no screen recording permission is needed. Fictional data only.
@MainActor
enum Snapshot {
    static func run(model: AppModel, directory: URL) async {
        let login = model.session.summaries.first { $0.title == "Forge Atlas" }
        // Sized once, before any capture: the window keeps that frame for every PNG.
        mainWindow?.setFrame(NSRect(x: 80, y: 80, width: 1280, height: 820), display: true)
        try? await Task.sleep(for: .milliseconds(800))

        for (suffix, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            NSApp.appearance = NSAppearance(named: appearance)
            model.editing = false
            model.selection = .all
            model.selectedItem = login.map { ItemRef(vaultID: $0.vaultId, itemID: $0.id) }
            await capture(directory, "mac-list-detail-\(suffix)")

            model.editing = true
            await capture(directory, "mac-edit-\(suffix)")
            model.editing = false

            if let atlas = model.session.vaults.first(where: { $0.meta.name == "Projet Atlas" }) {
                model.selection = .vault(atlas.id)
            }
            UserDefaults.standard.set(true, forKey: "onepass.browse.sortByDate")
            await capture(directory, "mac-vault-by-date-\(suffix)")
            UserDefaults.standard.set(false, forKey: "onepass.browse.sortByDate")

            model.selection = .trash
            model.selectedItem = nil
            await capture(directory, "mac-trash-\(suffix)")
        }
        NSApp.terminate(nil)
    }

    private static var mainWindow: NSWindow? {
        NSApp.windows.first { $0.isVisible && $0.contentView != nil && $0.canBecomeMain }
    }

    private static func capture(_ directory: URL, _ name: String) async {
        try? await Task.sleep(for: .milliseconds(1500))
        guard let frameView = mainWindow?.contentView?.superview else {
            DemoTrace.log("snapshot: no window (%d windows)", NSApp.windows.count)
            return
        }
        frameView.layoutSubtreeIfNeeded()
        frameView.displayIfNeeded()
        let bounds = frameView.bounds
        guard let rep = frameView.bitmapImageRepForCachingDisplay(in: bounds) else { return }
        frameView.cacheDisplay(in: bounds, to: rep)
        guard let data = rep.representation(using: .png, properties: [:]) else { return }
        try? data.write(to: directory.appendingPathComponent("\(name).png"))
        DemoTrace.log("snapshot: %@", name)
    }
}
#endif
