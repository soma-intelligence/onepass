import Foundation
import Testing

/// NFC Tag Reading (passport chips) is an iPhone capability: the iOS entitlement files carry
/// `com.apple.developer.nfc.readersession.formats = [TAG]`, the visionOS and macOS ones never do
/// (NFC does not exist there, and a profile without the capability would refuse the build).
@Suite("NFC entitlements")
struct NFCEntitlementTests {
    private static let appleDir = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()

    static let formats = "com.apple.developer.nfc.readersession.formats"

    private static func plist(_ path: String) throws -> [String: Any] {
        let data = try Data(contentsOf: appleDir.appendingPathComponent(path))
        return try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    }

    @Test(arguments: [
        "App/Support/OnePass-iOS.entitlements",
        "App/Support/OnePass-CloudKit.entitlements",
        "App/Support/OnePass-Signed-iOS.entitlements",
        "Personal.entitlements",
    ])
    func iPhoneFilesReadTags(path: String) throws {
        #expect(try Self.plist(path)[Self.formats] as? [String] == ["TAG"], "\(path) lacks \(Self.formats)")
    }

    @Test(arguments: [
        "App/Support/OnePass-CloudKit-visionOS.entitlements",
        "App/Support/OnePass-Signed-visionOS.entitlements",
        "App/Support/OnePass.entitlements",
        "App/Support/OnePass-CloudKit-macOS.entitlements",
        "App/Support/OnePass-Signed-macOS.entitlements",
    ])
    func otherPlatformsDoNot(path: String) throws {
        #expect(try Self.plist(path)[Self.formats] == nil, "\(path) carries \(Self.formats)")
    }

    /// Every signed visionOS configuration of the app points at a visionOS file.
    @Test func visionOSConfigurationsUseTheirOwnFiles() throws {
        let yml = try String(contentsOf: Self.appleDir.appendingPathComponent("project.yml"), encoding: .utf8)
        #expect(yml.contains("\"CODE_SIGN_ENTITLEMENTS[sdk=xr*]\": App/Support/OnePass-CloudKit-visionOS.entitlements"))
        #expect(yml.contains("\"CODE_SIGN_ENTITLEMENTS[sdk=xr*]\": App/Support/OnePass-Signed-visionOS.entitlements"))
        #expect(!yml.contains("\"CODE_SIGN_ENTITLEMENTS[sdk=xr*]\": App/Support/OnePass-Signed-iOS.entitlements"))
    }
}
