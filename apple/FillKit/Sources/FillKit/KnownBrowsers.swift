import Foundation

/// The Mac browsers, by bundle id: the one list the helper and the app's "Remplir partout" page
/// read (this file is also compiled into the Mac app, see `project.yml`). Only a browser may give
/// a URL target (`TargetResolver`); a browser is never remembered as an app, and the pill stays
/// out of browsers by default (their extension has its own). The server keeps the same list in
/// `core/onepass-core/src/fill_plan/app_entry.rs` (`KNOWN_BROWSERS`): change both together.
public enum KnownBrowsers {
    public static let bundleIDs: Set<String> = [
        // Safari
        "com.apple.Safari", "com.apple.SafariTechnologyPreview",
        // Chrome and Chromium
        "com.google.Chrome", "com.google.Chrome.beta", "com.google.Chrome.dev", "com.google.Chrome.canary",
        "org.chromium.Chromium",
        // Edge
        "com.microsoft.edgemac", "com.microsoft.edgemac.Beta", "com.microsoft.edgemac.Dev",
        "com.microsoft.edgemac.Canary",
        // Brave
        "com.brave.Browser", "com.brave.Browser.beta", "com.brave.Browser.nightly",
        // Vivaldi, Opera
        "com.vivaldi.Vivaldi", "com.operasoftware.Opera", "com.operasoftware.OperaGX",
        // Arc, Orion
        "company.thebrowser.Browser", "com.kagi.kagimacOS",
        // Firefox
        "org.mozilla.firefox", "org.mozilla.firefoxdeveloperedition", "org.mozilla.nightly",
        // Tor Browser, DuckDuckGo, Zen
        "org.torproject.torbrowser", "com.duckduckgo.macos.browser", "app.zen-browser.zen",
    ]

    private static let lowercased = Set(bundleIDs.map { $0.lowercased() })

    /// Whether `bundleID` is a known browser, compared without case (as Launch Services does).
    public static func contains(_ bundleID: String?) -> Bool {
        guard let bundleID else { return false }
        return lowercased.contains(bundleID.lowercased())
    }
}
