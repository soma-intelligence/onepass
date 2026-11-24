import Foundation

/// The helper's settings, read from the App Group defaults the Mac app's "Remplir partout" page
/// writes. The key names and defaults are `FillDefaults` (shared with the app). Every key is
/// optional: a missing or malformed one gives the default. Read on each refresh, so a change in
/// the app applies at the next field or shortcut.
struct FillSettings: Equatable {
    typealias Key = FillDefaults.Key

    static let defaultExcluded = FillDefaults.excludedApps
    static let defaultTypingDelayMs = FillDefaults.typingDelayMs
    /// At most this many excluded apps are read: the list is checked on every focus change.
    static let maxExcluded = 500

    /// `fill.enabled` as written by the app, nil when it never wrote it.
    var enabled: Bool?
    var pillEnabled = FillDefaults.pill
    var shortcutEnabled = FillDefaults.hotkey
    var hotkeyKeyCode = FillDefaults.hotkeyKeyCode
    var hotkeyModifiers = FillDefaults.hotkeyModifiers
    var excludedBundleIDs: Set<String>
    var typingDelayMs = Self.defaultTypingDelayMs

    /// The bundle id of the Mac app the helper ships in (`<app>.fill` minus `.fill`).
    let appBundleID: String?

    init(defaults: UserDefaults?, appBundleID: String?) {
        self.appBundleID = appBundleID
        let excluded = ((defaults?.array(forKey: Key.excluded) as? [String]) ?? Self.defaultExcluded)
            .prefix(Self.maxExcluded)
        excludedBundleIDs = Set(excluded + [appBundleID].compactMap { $0 })
        guard let defaults else { return }
        enabled = defaults.object(forKey: Key.enabled) as? Bool
        if let on = defaults.object(forKey: Key.pill) as? Bool { pillEnabled = on }
        if let on = defaults.object(forKey: Key.hotkey) as? Bool { shortcutEnabled = on }
        if let ms = defaults.object(forKey: Key.typingDelayMs) as? Int {
            typingDelayMs = min(max(ms, FillDefaults.typingDelayRange.lowerBound), FillDefaults.typingDelayRange.upperBound)
        }
        // The key and its modifiers go together: a bad pair gives the default pair.
        if let code = defaults.object(forKey: Key.hotkeyKeyCode) as? Int,
            let modifiers = defaults.object(forKey: Key.hotkeyModifiers) as? Int,
            (0...127).contains(code), FillDefaults.isValidHotkey(modifiers: modifiers)
        {
            hotkeyKeyCode = code
            hotkeyModifiers = FillDefaults.cleanModifiers(modifiers)
        }
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
