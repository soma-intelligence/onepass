import Foundation

/// The helper's settings, read from the App Group defaults the Mac app's "Fill anywhere" page
/// writes (Task 9). Every key is optional: a missing or malformed one gives the default. Read on
/// each use, so a change in the app applies at the next field or shortcut.
struct FillSettings: Equatable {
    /// Keys in the App Group defaults (suite `OnePassAppGroup`).
    enum Key {
        /// Bool, default true: the pill shows next to password fields.
        static let pillEnabled = "fill.pillEnabled"
        /// Bool, default true: ⌥⌘\ opens the picker.
        static let shortcutEnabled = "fill.shortcutEnabled"
        /// [String] of bundle ids where the pill never shows, default `defaultExcluded`. The
        /// helper's own app is always added. The shortcut still works there.
        static let excludedBundleIDs = "fill.excludedBundleIDs"
        /// Int, milliseconds between two typed keys, default 8, kept within 0...200.
        static let typingDelayMs = "fill.typingDelayMs"
    }

    static let defaultExcluded = ["com.apple.Terminal", "com.googlecode.iterm2"]
    static let defaultTypingDelayMs = 8

    var pillEnabled = true
    var shortcutEnabled = true
    var excludedBundleIDs: Set<String>
    var typingDelayMs = Self.defaultTypingDelayMs

    /// The bundle id of the Mac app the helper ships in (`<app>.fill` minus `.fill`).
    let appBundleID: String?

    init(defaults: UserDefaults?, appBundleID: String?) {
        self.appBundleID = appBundleID
        let excluded = (defaults?.array(forKey: Key.excludedBundleIDs) as? [String]) ?? Self.defaultExcluded
        excludedBundleIDs = Set(excluded + [appBundleID].compactMap { $0 })
        guard let defaults else { return }
        if let on = defaults.object(forKey: Key.pillEnabled) as? Bool { pillEnabled = on }
        if let on = defaults.object(forKey: Key.shortcutEnabled) as? Bool { shortcutEnabled = on }
        if let ms = defaults.object(forKey: Key.typingDelayMs) as? Int { typingDelayMs = min(max(ms, 0), 200) }
    }

    /// The settings as they are now.
    static func current(bundle: Bundle = .main) -> FillSettings {
        FillSettings(defaults: sharedDefaults(bundle: bundle), appBundleID: appBundleID(bundle: bundle))
    }

    func isExcluded(_ bundleID: String?) -> Bool {
        guard let bundleID else { return false }
        return excludedBundleIDs.contains(bundleID)
    }

    /// The App Group defaults, the group from the `OnePassAppGroup` Info.plist key (as
    /// `BridgeLink.socketPath`). Nil when the build carries no group.
    static func sharedDefaults(bundle: Bundle) -> UserDefaults? {
        guard let raw = bundle.object(forInfoDictionaryKey: "OnePassAppGroup") as? String else { return nil }
        let group = raw.trimmingCharacters(in: .whitespaces)
        guard !group.isEmpty, !group.contains("$(") else { return nil }
        return UserDefaults(suiteName: group)
    }

    static func appBundleID(bundle: Bundle) -> String? {
        guard let own = bundle.bundleIdentifier, own.hasSuffix(".fill") else { return nil }
        return String(own.dropLast(".fill".count))
    }
}
