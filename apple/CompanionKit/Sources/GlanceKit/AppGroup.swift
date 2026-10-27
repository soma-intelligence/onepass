import Foundation

public enum AppGroup {
    public static let identifier = "group.me.somalabs.onepass"

    public static func containerURL() -> URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)
    }
}
