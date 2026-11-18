import Foundation

/// The few words DesignBridgeKit writes itself, localised in the package (en, fr, es, it). Apps
/// still pass their own copy for everything they show.
public enum DBStrings {
    public static var retry: String { String(localized: "db.retry", defaultValue: "Retry", bundle: .module) }
    public static var tryAgain: String { String(localized: "db.tryAgain", defaultValue: "Try again", bundle: .module) }
    public static var undo: String { String(localized: "db.undo", defaultValue: "Undo", bundle: .module) }
    public static var copied: String { String(localized: "db.copied", defaultValue: "Copied", bundle: .module) }
    public static var dismiss: String { String(localized: "db.dismiss", defaultValue: "Dismiss", bundle: .module) }
    public static var loading: String { String(localized: "db.loading", defaultValue: "Loading", bundle: .module) }
    public static var couldNotLoad: String {
        String(localized: "db.couldNotLoad", defaultValue: "Couldn't load", bundle: .module)
    }
    public static var offlineTitle: String {
        String(localized: "db.offline.title", defaultValue: "You're offline", bundle: .module)
    }
    public static var offlineMessage: String {
        String(localized: "db.offline.message", defaultValue: "Connect to the internet, then try again.", bundle: .module)
    }
    public static var genericMessage: String {
        String(localized: "db.generic.message", defaultValue: "This didn't load. Try again in a moment.", bundle: .module)
    }
}
