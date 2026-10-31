import Foundation

/// The App Group the app shares with its widgets, its notification extension and the AutoFill
/// extension. The identifier comes from the `OnePassAppGroup` Info.plist key, set to
/// `$(ONEPASS_APP_GROUP)`, the same build setting the entitlements name, so a personal team build
/// changes the setting only (apple/project.yml).
public enum AppGroup {
    /// The Soma Labs group, used when the bundle does not name one.
    public static let defaultIdentifier = "group.me.somalabs.onepass"
    public static let infoKey = "OnePassAppGroup"

    public static var identifier: String { identifier(bundle: .main) }

    /// The `OnePassAppGroup` key of `bundle`, else `defaultIdentifier` when it is missing, empty or
    /// left unexpanded.
    public static func identifier(bundle: Bundle) -> String {
        if let value = bundle.object(forInfoDictionaryKey: infoKey) as? String {
            let trimmed = value.trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty, !trimmed.contains("$(") { return trimmed }
        }
        return defaultIdentifier
    }

    public static func containerURL() -> URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)
    }
}
