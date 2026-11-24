import Foundation

public enum FillTarget: Equatable, Sendable {
    case url(URL)
    case app(bundleID: String, windowTitle: String?)
}

public enum TargetResolver {
    /// A page's origin (`http` or `https`) when the field is in a known browser, else the app.
    /// Any app can put a URL in `AXURL` or `AXDocument`: only a browser may claim a web origin,
    /// so a native app that names `https://accounts.google.com` still gets its own app target.
    public static func target(for f: FieldSnapshot) -> FillTarget {
        if KnownBrowsers.contains(f.bundleID), let url = f.url, let scheme = url.scheme?.lowercased(),
            scheme == "http" || scheme == "https"
        {
            return .url(url)
        }
        return .app(bundleID: f.bundleID, windowTitle: f.windowTitle)
    }
}
