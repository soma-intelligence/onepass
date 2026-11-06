import Foundation
import Testing

/// The agent-request alert is made time sensitive by the Notification Service Extension
/// (`NotificationService.swift` sets `interruptionLevel = .timeSensitive`), not by the push: a
/// CloudKit alert cannot carry an interruption level. The level is honoured only when the bundle
/// that sets it holds `com.apple.developer.usernotifications.time-sensitive`, so the app (which
/// receives the push) and the extension (which raises the level) both carry it in every
/// configuration that subscribes to the push (`Release-CloudKit`, the founder's install).
/// `OnePassNotifications-NoGroup.entitlements` stays empty: it exists only for a personal profile
/// that has neither the App Group nor the capability yet (`scripts/install-iphone.sh`).
@Suite("Notification entitlements")
struct NotificationEntitlementTests {
    private static let appleDir = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()

    static let timeSensitive = "com.apple.developer.usernotifications.time-sensitive"

    private static func plist(_ path: String) throws -> [String: Any] {
        let data = try Data(contentsOf: appleDir.appendingPathComponent(path))
        return try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    }

    @Test(arguments: [
        "App/Support/OnePass-CloudKit.entitlements",
        "NotificationService/OnePassNotifications.entitlements",
    ])
    func timeSensitiveOnTheAppAndTheExtension(path: String) throws {
        #expect(try Self.plist(path)[Self.timeSensitive] as? Bool == true, "\(path) lacks \(Self.timeSensitive)")
    }

    /// The extension keeps its App Group next to the new key (the Mac names come from it).
    @Test func extensionKeepsItsAppGroup() throws {
        let ents = try Self.plist("NotificationService/OnePassNotifications.entitlements")
        #expect(ents["com.apple.security.application-groups"] as? [String] == ["$(ONEPASS_APP_GROUP)"])
    }

    /// The fallback for a profile without the capability: anything in it must exist in that profile.
    @Test func noGroupVariantStaysEmpty() throws {
        #expect(try Self.plist("NotificationService/OnePassNotifications-NoGroup.entitlements").isEmpty)
    }

    /// The extension is what raises the level: if it stops doing so, the entitlement is dead weight.
    @Test func extensionRaisesTheInterruptionLevel() throws {
        let source = try String(
            contentsOf: Self.appleDir.appendingPathComponent("NotificationService/NotificationService.swift"),
            encoding: .utf8)
        #expect(source.contains("interruptionLevel = .timeSensitive"))
    }
}
