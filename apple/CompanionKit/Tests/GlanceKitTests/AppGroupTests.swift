import Foundation
import Testing

@testable import GlanceKit

/// The widgets read the App Group the entitlements name (`OnePassAppGroup` = `$(ONEPASS_APP_GROUP)`).
@Suite("App Group identifier")
struct AppGroupTests {
    private static func bundle(_ info: [String: Any]) throws -> Bundle {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("onepass-app-group-\(UUID().uuidString).bundle", isDirectory: true)
        let contents = root.appendingPathComponent("Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
        var plist = info
        plist["CFBundleIdentifier"] = "me.somalabs.onepass.tests.\(UUID().uuidString)"
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            .write(to: contents.appendingPathComponent("Info.plist"))
        return try #require(Bundle(url: root))
    }

    @Test func groupComesFromTheInfoPlistKey() throws {
        let bundle = try Self.bundle(["OnePassAppGroup": " group.me.example.onepass "])
        #expect(AppGroup.identifier(bundle: bundle) == "group.me.example.onepass")
    }

    @Test(arguments: [nil, "", "$(ONEPASS_APP_GROUP)"] as [String?])
    func missingOrUnexpandedKeyFallsBackToTheDefault(value: String?) throws {
        let bundle = try Self.bundle(value.map { ["OnePassAppGroup": $0] } ?? [:])
        #expect(AppGroup.identifier(bundle: bundle) == "group.me.somalabs.onepass")
    }
}
