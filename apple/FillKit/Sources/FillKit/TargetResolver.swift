import Foundation

public enum FillTarget: Equatable, Sendable {
    case url(URL)
    case app(bundleID: String, windowTitle: String?)
}

public enum TargetResolver {
    public static func target(for f: FieldSnapshot) -> FillTarget {
        if let url = f.url, let scheme = url.scheme?.lowercased(),
            scheme == "http" || scheme == "https"
        {
            return .url(url)
        }
        return .app(bundleID: f.bundleID, windowTitle: f.windowTitle)
    }
}
