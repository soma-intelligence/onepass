import Foundation
import Testing

@testable import VaultKit

/// The shared keychain group comes from one build setting, `ONEPASS_KEYCHAIN_GROUP`: the entitlements
/// name it and the Info.plist key `OnePassKeychainGroup` hands it to the code (the App Group and the
/// bundle ids follow the same rule: `ONEPASS_APP_GROUP`, `ONEPASS_BUNDLE_ID_PREFIX`). A personal build that
/// changed the entitlements alone got errSecMissingEntitlement at unlock; these tests keep the two
/// from drifting again.
@Suite("Keychain group setting")
struct KeychainGroupSettingTests {
    // MARK: - Info.plist reading

    /// A throwaway bundle whose Info.plist holds `info`.
    private static func bundle(_ info: [String: Any]) throws -> Bundle {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("onepass-keychain-group-\(UUID().uuidString).bundle", isDirectory: true)
        let contents = root.appendingPathComponent("Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
        var plist = info
        plist["CFBundleIdentifier"] = "me.somalabs.onepass.tests.\(UUID().uuidString)"
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try data.write(to: contents.appendingPathComponent("Info.plist"))
        return try #require(Bundle(url: root))
    }

    @Test func groupComesFromTheInfoPlistKey() throws {
        let bundle = try Self.bundle([
            "AppIdentifierPrefix": "ABCDE12345.",
            "OnePassKeychainGroup": "me.example.fork.shared",
        ])
        #expect(VaultEnvironment.keychainGroup(bundle: bundle) == "me.example.fork.shared")
        #expect(VaultEnvironment.sharedAccessGroup(bundle: bundle) == "ABCDE12345.me.example.fork.shared")
    }

    @Test func missingKeyFallsBackToTheDefaultGroup() throws {
        let bundle = try Self.bundle(["AppIdentifierPrefix": "ABCDE12345."])
        #expect(VaultEnvironment.keychainGroup(bundle: bundle) == "me.somalabs.onepass.shared")
        #expect(VaultEnvironment.sharedAccessGroup(bundle: bundle) == "ABCDE12345.me.somalabs.onepass.shared")
    }

    @Test(arguments: ["$(ONEPASS_KEYCHAIN_GROUP)", "", "   "])
    func unexpandedOrEmptyKeyFallsBackToTheDefaultGroup(value: String) throws {
        let bundle = try Self.bundle(["AppIdentifierPrefix": "ABCDE12345", "OnePassKeychainGroup": value])
        #expect(VaultEnvironment.keychainGroup(bundle: bundle) == VaultEnvironment.defaultKeychainGroup)
        // The prefix gains its dot when the Info.plist value has none.
        #expect(VaultEnvironment.sharedAccessGroup(bundle: bundle) == "ABCDE12345.me.somalabs.onepass.shared")
    }

    @Test func surroundingSpacesAreTrimmed() throws {
        let bundle = try Self.bundle(["OnePassKeychainGroup": "  me.example.fork.shared "])
        #expect(VaultEnvironment.keychainGroup(bundle: bundle) == "me.example.fork.shared")
    }

    @Test func defaultGroupNeverChanges() {
        // Existing users' Secret Keys and Secure Enclave keys live in this group.
        #expect(VaultEnvironment.defaultKeychainGroup == "me.somalabs.onepass.shared")
    }

    // MARK: - Source check: entitlements, project.yml, Info.plist files, generated project

    /// `apple/`, from this file (`apple/VaultKit/Tests/VaultKitTests/`).
    private static let appleDir = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()

    static let settingReference = "$(AppIdentifierPrefix)$(ONEPASS_KEYCHAIN_GROUP)"

    /// Every `.entitlements` file of the Apple apps (build output folders skipped).
    private static func entitlementFiles() -> [URL] {
        let fm = FileManager.default
        guard let walker = fm.enumerator(at: appleDir, includingPropertiesForKeys: [.isDirectoryKey]) else { return [] }
        var found: [URL] = []
        for case let url as URL in walker {
            let name = url.lastPathComponent
            if name.hasPrefix("DerivedData") || name == "build" || name == ".build" || name == "node_modules" {
                walker.skipDescendants()
                continue
            }
            if url.pathExtension == "entitlements" { found.append(url) }
        }
        return found.sorted { $0.path < $1.path }
    }

    @Test func everyKeychainGroupEntitlementNamesTheBuildSetting() throws {
        let files = Self.entitlementFiles()
        #expect(files.count >= 8, "entitlements files not found under \(Self.appleDir.path)")
        var withGroups = 0
        for file in files {
            let data = try Data(contentsOf: file)
            let plist = try #require(
                try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                "\(file.lastPathComponent) is not a dictionary")
            guard let groups = plist["keychain-access-groups"] else { continue }
            withGroups += 1
            let list = try #require(groups as? [String], "\(file.lastPathComponent): keychain-access-groups is not a list")
            #expect(
                list == [Self.settingReference],
                """
                \(file.path): keychain-access-groups must be exactly ["\(Self.settingReference)"], \
                found \(list). Change the group with the ONEPASS_KEYCHAIN_GROUP build setting \
                (apple/project.yml), never in an entitlements file.
                """)
        }
        // The app (iOS, signed macOS, CloudKit) and the AutoFill extension carry the group.
        #expect(withGroups >= 6)
    }

    static let appGroupReference = "$(ONEPASS_APP_GROUP)"

    @Test func everyAppGroupEntitlementNamesTheBuildSetting() throws {
        var withGroups = 0
        for file in Self.entitlementFiles() {
            let data = try Data(contentsOf: file)
            let plist = try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
            guard let groups = plist["com.apple.security.application-groups"] else { continue }
            withGroups += 1
            #expect(
                groups as? [String] == [Self.appGroupReference],
                """
                \(file.path): com.apple.security.application-groups must be exactly ["\(Self.appGroupReference)"], \
                found \(groups). Change the group with the ONEPASS_APP_GROUP build setting (apple/project.yml).
                """)
        }
        // App (iOS, signed and CloudKit, both platforms), AutoFill, widgets, notifications, Safari.
        #expect(withGroups >= 10)
    }

    @Test(arguments: ["App/Support/Info.plist", "AutoFill/Support/Info.plist", "Widgets/Info.plist", "NotificationService/Info.plist"])
    func infoPlistHandsTheAppGroupToTheCode(path: String) throws {
        let data = try Data(contentsOf: Self.appleDir.appendingPathComponent(path))
        let plist = try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        #expect(plist["OnePassAppGroup"] as? String == Self.appGroupReference)
    }

    @Test func shippedBundleIdsDeriveFromTheBuildSetting() throws {
        let yml = try String(contentsOf: Self.appleDir.appendingPathComponent("project.yml"), encoding: .utf8)
        #expect(yml.contains("ONEPASS_BUNDLE_ID_PREFIX: me.somalabs.onepass\n"))
        for suffix in ["", ".autofill", ".safari", ".widgets", ".notifications", ".watchkitapp", ".watchkitapp.widgets"] {
            #expect(yml.contains("PRODUCT_BUNDLE_IDENTIFIER: $(ONEPASS_BUNDLE_ID_PREFIX)\(suffix)\n"), "\(suffix)")
            #expect(!yml.contains("PRODUCT_BUNDLE_IDENTIFIER: me.somalabs.onepass\(suffix)\n"), "\(suffix)")
        }
        #expect(yml.contains("WKCompanionAppBundleIdentifier: $(ONEPASS_BUNDLE_ID_PREFIX)\n"))
    }

    @Test func projectDefinesTheSettingWithTheDefaultGroup() throws {
        let yml = try String(contentsOf: Self.appleDir.appendingPathComponent("project.yml"), encoding: .utf8)
        #expect(yml.contains("ONEPASS_KEYCHAIN_GROUP: \(VaultEnvironment.defaultKeychainGroup)\n"))
        let infoLine = "OnePassKeychainGroup: $(ONEPASS_KEYCHAIN_GROUP)"
        #expect(yml.components(separatedBy: infoLine).count - 1 >= 2, "the OnePass and OnePassAutoFill Info.plist need \(infoLine)")
        // The committed project was regenerated from it.
        let pbxproj = try String(
            contentsOf: Self.appleDir.appendingPathComponent("OnePass.xcodeproj/project.pbxproj"), encoding: .utf8)
        #expect(pbxproj.contains("ONEPASS_KEYCHAIN_GROUP = \(VaultEnvironment.defaultKeychainGroup);"))
    }

    @Test(arguments: ["App/Support/Info.plist", "AutoFill/Support/Info.plist"])
    func infoPlistHandsTheSettingToTheCode(path: String) throws {
        let data = try Data(contentsOf: Self.appleDir.appendingPathComponent(path))
        let plist = try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        #expect(plist[VaultEnvironment.keychainGroupInfoKey] as? String == "$(ONEPASS_KEYCHAIN_GROUP)")
        #expect(plist["AppIdentifierPrefix"] as? String == "$(AppIdentifierPrefix)")
    }
}
