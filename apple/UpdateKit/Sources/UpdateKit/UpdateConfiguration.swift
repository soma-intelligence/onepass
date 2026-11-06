import Foundation

/// The update settings of the running app, read from its Info.plist and checked before Sparkle
/// starts (spec section 5). Sparkle enforces the same flags; checking them here too means a build
/// that would weaken them never starts an updater at all.
public struct UpdateConfiguration: Equatable, Sendable {
    public let feedURL: URL
    /// Base64 Ed25519 public key (`SUPublicEDKey`) the archive and the feed must be signed with.
    public let publicEDKey: String

    public enum Status: Equatable, Sendable {
        case enabled(UpdateConfiguration)
        /// No public key: a development or ad hoc build. No updater, no menu item.
        case disabled
        /// A key is there but a setting is unsafe or malformed: no updater either.
        case invalid(Problem)
    }

    public enum Problem: String, Error, Sendable {
        case invalidPublicKey
        case missingFeed
        case insecureFeed
        case unsignedFeedAllowed
        case extractionBeforeVerification
        case systemProfilingOn
    }

    public static func status(info: [String: Any]) -> Status {
        let key = (info["SUPublicEDKey"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty else { return .disabled }
        guard let raw = Data(base64Encoded: key), raw.count == 32 else { return .invalid(.invalidPublicKey) }
        let feed = (info["SUFeedURL"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !feed.isEmpty else { return .invalid(.missingFeed) }
        guard let url = URL(string: feed), url.scheme == "https", let host = url.host(), !host.isEmpty else {
            return .invalid(.insecureFeed)
        }
        guard bool(info["SURequireSignedFeed"]) == true else { return .invalid(.unsignedFeedAllowed) }
        guard bool(info["SUVerifyUpdateBeforeExtraction"]) == true else { return .invalid(.extractionBeforeVerification) }
        guard bool(info["SUEnableSystemProfiling"]) != true else { return .invalid(.systemProfilingOn) }
        return .enabled(UpdateConfiguration(feedURL: url, publicEDKey: key))
    }

    /// An Info.plist boolean: `<true/>`, or the string a build setting leaves (`YES`, `true`).
    static func bool(_ value: Any?) -> Bool? {
        switch value {
        case let flag as Bool: flag
        case let text as String:
            switch text.lowercased() {
            case "yes", "true", "1": true
            case "no", "false", "0": false
            default: nil
            }
        default: nil
        }
    }
}

/// OnePass's own downgrade guard, on top of Sparkle's: an update is offered only when its
/// `sparkle:version` is strictly greater than the installed `CFBundleVersion`, both read as dotted
/// numbers. Anything else (a suffix, an empty part, a letter) is refused.
public enum UpdateVersionPolicy {
    public static func components(_ version: String) -> [Int]? {
        let parts = version.split(separator: ".", omittingEmptySubsequences: false)
        guard !parts.isEmpty else { return nil }
        var numbers: [Int] = []
        for part in parts {
            guard !part.isEmpty, part.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }), let n = Int(part) else { return nil }
            numbers.append(n)
        }
        return numbers
    }

    public static func isUpgrade(from current: String, to offered: String) -> Bool {
        guard let a = components(current), let b = components(offered) else { return false }
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0
            let y = i < b.count ? b[i] : 0
            if x != y { return y > x }
        }
        return false
    }
}
