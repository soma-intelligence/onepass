import Foundation

/// The names and defaults of the settings OnePass Fill reads and the Mac app's "Remplir partout"
/// page writes, in the App Group defaults (suite: the `OnePassAppGroup` Info.plist key of each
/// bundle, set to the same build setting). One file, compiled into both targets (the helper's
/// `Fill` sources, and the app's macOS sources in `project.yml`), so the names cannot drift.
/// Foundation only: no Carbon here, the key codes and modifier bits are written as numbers.
enum FillDefaults {
    enum Key {
        /// Bool, default false: the user turned the helper on (the login item is registered).
        static let enabled = "fill.enabled"
        /// Bool, default true: the pill shows next to password fields.
        static let pill = "fill.pill"
        /// Bool, default true: the shortcut opens the picker.
        static let hotkey = "fill.hotkey"
        /// Int, a virtual key code (`kVK_*`), default `hotkeyKeyCode` (backslash).
        static let hotkeyKeyCode = "fill.hotkeyKeyCode"
        /// Int, Carbon modifier flags (`cmdKey`, `optionKey`, ...), default `hotkeyModifiers`.
        static let hotkeyModifiers = "fill.hotkeyModifiers"
        /// [String] of bundle ids where the pill never shows, default `excluded(appBundleID:)`.
        /// The shortcut still works there.
        static let excluded = "fill.excluded"
        /// Int, milliseconds between two typed keys, default 8, kept within `typingDelayRange`.
        static let typingDelayMs = "fill.typingDelayMs"
        /// Bool, written by the helper only: its `AXIsProcessTrusted()`, at launch and on change.
        static let trusted = "fill.trusted"
    }

    static let enabled = false
    static let pill = true
    static let hotkey = true
    /// `kVK_ANSI_Backslash`.
    static let hotkeyKeyCode = 0x2A
    /// Carbon modifier bits (`Carbon.HIToolbox` `Events.h`).
    static let cmdKey = 0x0100
    static let shiftKey = 0x0200
    static let optionKey = 0x0800
    static let controlKey = 0x1000
    /// ⌥⌘.
    static let hotkeyModifiers = optionKey | cmdKey
    static let typingDelayMs = 8
    static let typingDelayRange = 0...200
    /// Terminals, where a password field is rare and a pill would be in the way.
    static let excludedApps = ["com.apple.Terminal", "com.googlecode.iterm2"]

    /// The default excluded list: the terminals and the OnePass app itself.
    static func excluded(appBundleID: String?) -> [String] {
        excludedApps + [appBundleID].compactMap { $0 }
    }

    /// A shortcut needs ⌘, ⌥ or ⌃ (Shift alone would take a plain character from every app).
    static func isValidHotkey(modifiers: Int) -> Bool {
        modifiers & (cmdKey | optionKey | controlKey) != 0
    }

    /// Only the modifier bits a shortcut may carry.
    static func cleanModifiers(_ modifiers: Int) -> Int {
        modifiers & (cmdKey | shiftKey | optionKey | controlKey)
    }

    /// Posted (no user info) by the app after it writes a setting, named after the app's bundle
    /// id so another build's helper does not react. The helper reads the settings again at once;
    /// it also reads them every few seconds, so a missed notification only delays a change.
    static func changedNotification(appBundleID: String) -> Notification.Name {
        Notification.Name("\(appBundleID).fill.settingsChanged")
    }
}
