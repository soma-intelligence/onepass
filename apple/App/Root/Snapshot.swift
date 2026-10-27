#if DEBUG && os(macOS)
import AppKit
import SwiftUI
import VaultKit

/// `-OnePassSnapshot <folder>` (Debug, Mac): with the demo data, renders the app's own window
/// (frame and toolbar included) into PNGs at 1280 x 820, light then dark, then quits. Uses
/// `cacheDisplay`, so no screen recording permission is needed. Fictional data only.
/// Screens: list and detail, edit, vault by date, trash, search, Bienvenue, Réglages (its own
/// window), then the lock screen last (`scripts/screenshots.sh`).
@MainActor
enum Snapshot {
    static func run(model: AppModel, directory: URL) async {
        let login = model.session.summaries.first { $0.title == "Forge Atlas" }
        // Sized once, before any capture, and made key (an inactive window draws its sidebar
        // and selection differently). Placed off the visible screen area.
        NSApp.activate()
        mainWindow?.setFrame(NSRect(x: -4000, y: 80, width: 1280, height: 820), display: true)
        mainWindow?.makeKeyAndOrderFront(nil)
        try? await Task.sleep(for: .milliseconds(800))
        logMenus()

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
            DemoData.defaults.set(true, forKey: "onepass.browse.sortByDate")
            await capture(directory, "mac-vault-by-date-\(suffix)")
            DemoData.defaults.set(false, forKey: "onepass.browse.sortByDate")

            model.selection = .trash
            model.selectedItem = nil
            await capture(directory, "mac-trash-\(suffix)")

            model.selection = .all
            model.selectedItem = login.map { ItemRef(vaultID: $0.vaultId, itemID: $0.id) }
            model.searchFocusRequest &+= 1
            try? await Task.sleep(for: .milliseconds(600))
            DemoTrace.log("search: trash command enabled %@", trashEnabled ? "yes" : "no")
            DemoTrace.log("search: first responder %@", mainWindow?.firstResponder.map { String(describing: type(of: $0)) } ?? "nil")
            await capture(directory, "mac-search-\(suffix)")
            // As a click in the item list would: the list's table takes the focus, then ⌘F again.
            if let table = itemTable { mainWindow?.makeFirstResponder(table) }
            try? await Task.sleep(for: .milliseconds(300))
            DemoTrace.log("list focused: trash command enabled %@ (window key %@, app active %@)", trashEnabled ? "yes" : "no",
                mainWindow?.isKeyWindow == true ? "yes" : "no", NSApp.isActive ? "yes" : "no")
            DemoTrace.log("search left: first responder %@", mainWindow?.firstResponder.map { String(describing: type(of: $0)) } ?? "nil")
            model.searchFocusRequest &+= 1
            try? await Task.sleep(for: .milliseconds(600))
            DemoTrace.log("search again: first responder %@", mainWindow?.firstResponder.map { String(describing: type(of: $0)) } ?? "nil")
            if let table = itemTable { mainWindow?.makeFirstResponder(table) }

            // Bienvenue: the onboarding's first step, shown over the unlocked demo session.
            model.selectedItem = nil
            model.onboardingInProgress = true
            await capture(directory, "mac-welcome-\(suffix)")
            model.onboardingInProgress = false

            await captureSettings(directory, "mac-settings-\(suffix)")
        }
        // The lock screen last: the demo session is not unlocked again.
        model.lock()
        for (suffix, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            NSApp.appearance = NSAppearance(named: appearance)
            await capture(directory, "mac-locked-\(suffix)")
        }
        NSApp.terminate(nil)
    }

    /// Opens the `Settings` window through its menu item (⌘,), renders it, then closes it.
    private static func captureSettings(_ directory: URL, _ name: String) async {
        func find(_ menu: NSMenu) -> NSMenuItem? {
            for item in menu.items {
                if item.keyEquivalent == ",", item.keyEquivalentModifierMask.contains(.command) { return item }
                if let sub = item.submenu, let found = find(sub) { return found }
            }
            return nil
        }
        guard let main = NSApp.mainMenu, let item = find(main), let menu = item.menu else {
            DemoTrace.log("snapshot: no settings menu item")
            return
        }
        let index = menu.index(of: item)
        let appWindow = mainWindow
        menu.performActionForItem(at: index)
        try? await Task.sleep(for: .milliseconds(1500))
        // The settings window is created once, then reused (hidden) by the next ⌘,.
        guard let window = NSApp.windows.first(where: { $0.isVisible && $0 !== appWindow && $0.contentView != nil })
        else {
            DemoTrace.log("snapshot: settings window not found")
            return
        }
        render(window, directory, name)
        window.close()
        try? await Task.sleep(for: .milliseconds(300))
    }

    /// Menu items bound to ⌘F and ⌘⌫, to check that each has one owner.
    private static func logMenus() {
        func walk(_ menu: NSMenu, _ path: String) {
            for item in menu.items {
                let key = item.keyEquivalent
                if item.keyEquivalentModifierMask.contains(.command), key == "f" || key == "\u{8}" || key == "l" || key == "n" {
                    DemoTrace.log("menu: %@ > %@ [cmd-%@]", path, item.title, key == "\u{8}" ? "delete" : key)
                }
                if let sub = item.submenu { walk(sub, path + " > " + item.title) }
            }
        }
        if let main = NSApp.mainMenu { walk(main, "") }
    }

    /// Whether the ⌘⌫ menu item is enabled right now.
    private static var trashEnabled: Bool {
        NSApp.mainMenu?.update()
        func walk(_ menu: NSMenu) -> NSMenuItem? {
            for item in menu.items {
                if item.keyEquivalent == "\u{8}", item.keyEquivalentModifierMask.contains(.command) { return item }
                if let sub = item.submenu, let found = walk(sub) { return found }
            }
            return nil
        }
        return NSApp.mainMenu.flatMap(walk)?.isEnabled ?? false
    }

    /// The item list's table (the one right of the sidebar).
    private static var itemTable: NSView? {
        guard let root = mainWindow?.contentView else { return nil }
        var found: [NSTableView] = []
        func walk(_ view: NSView) {
            if let table = view as? NSTableView { found.append(table) }
            view.subviews.forEach(walk)
        }
        walk(root)
        return found.max { $0.convert($0.bounds, to: nil).minX < $1.convert($1.bounds, to: nil).minX }
    }

    private static var mainWindow: NSWindow? {
        NSApp.windows.first { $0.isVisible && $0.contentView != nil && $0.canBecomeMain }
    }

    private static func capture(_ directory: URL, _ name: String) async {
        try? await Task.sleep(for: .milliseconds(1500))
        guard let window = mainWindow else {
            DemoTrace.log("snapshot: no window (%d windows)", NSApp.windows.count)
            return
        }
        render(window, directory, name)
    }

    /// Renders a window, frame and toolbar included, into `<directory>/<name>.png`.
    private static func render(_ window: NSWindow, _ directory: URL, _ name: String) {
        guard let frameView = window.contentView?.superview else { return }
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
