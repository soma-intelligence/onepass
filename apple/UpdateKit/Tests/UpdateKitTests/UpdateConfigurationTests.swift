import Foundation
import Testing
@testable import UpdateKit

@Suite struct UpdateConfigurationTests {
    static let key = Data(repeating: 7, count: 32).base64EncodedString()
    static let feed = "https://github.com/soma-intelligence/onepass/releases/latest/download/appcast.xml"

    static func info(_ overrides: [String: Any?] = [:]) -> [String: Any] {
        var info: [String: Any] = [
            "SUFeedURL": feed,
            "SUPublicEDKey": key,
            "SURequireSignedFeed": true,
            "SUVerifyUpdateBeforeExtraction": true,
            "SUEnableSystemProfiling": false,
        ]
        for (k, v) in overrides {
            info[k] = v
        }
        return info
    }

    @Test func aDevelopmentBuildWithoutKeyIsDisabled() {
        #expect(UpdateConfiguration.status(info: Self.info(["SUPublicEDKey": ""])) == .disabled)
        #expect(UpdateConfiguration.status(info: Self.info(["SUPublicEDKey": nil])) == .disabled)
        #expect(UpdateConfiguration.status(info: Self.info(["SUPublicEDKey": "  "])) == .disabled)
    }

    @Test func theShippedSettingsAreEnabled() {
        let expected = UpdateConfiguration(feedURL: URL(string: Self.feed)!, publicEDKey: Self.key)
        #expect(UpdateConfiguration.status(info: Self.info()) == .enabled(expected))
        // Booleans may reach the Info.plist as strings through a build setting.
        #expect(UpdateConfiguration.status(info: Self.info([
            "SURequireSignedFeed": "YES", "SUVerifyUpdateBeforeExtraction": "true", "SUEnableSystemProfiling": nil,
        ])) == .enabled(expected))
    }

    @Test func aKeyThatIsNot32BytesIsInvalid() {
        for bad in ["abc", Data(count: 31).base64EncodedString(), Data(count: 64).base64EncodedString(), "%%%%"] {
            #expect(UpdateConfiguration.status(info: Self.info(["SUPublicEDKey": bad])) == .invalid(.invalidPublicKey))
        }
    }

    @Test func theFeedMustBeHTTPS() {
        #expect(UpdateConfiguration.status(info: Self.info(["SUFeedURL": nil])) == .invalid(.missingFeed))
        #expect(UpdateConfiguration.status(info: Self.info(["SUFeedURL": ""])) == .invalid(.missingFeed))
        #expect(UpdateConfiguration.status(info: Self.info(["SUFeedURL": "http://github.com/a.xml"])) == .invalid(.insecureFeed))
        #expect(UpdateConfiguration.status(info: Self.info(["SUFeedURL": "https://"])) == .invalid(.insecureFeed))
    }

    @Test func weakSparkleSettingsAreInvalid() {
        #expect(UpdateConfiguration.status(info: Self.info(["SURequireSignedFeed": false])) == .invalid(.unsignedFeedAllowed))
        #expect(UpdateConfiguration.status(info: Self.info(["SURequireSignedFeed": nil])) == .invalid(.unsignedFeedAllowed))
        #expect(UpdateConfiguration.status(info: Self.info(["SUVerifyUpdateBeforeExtraction": "NO"])) == .invalid(.extractionBeforeVerification))
        #expect(UpdateConfiguration.status(info: Self.info(["SUEnableSystemProfiling": true])) == .invalid(.systemProfilingOn))
    }
}

@Suite struct UpdateVersionPolicyTests {
    @Test func onlyAStrictlyNewerVersionIsAnUpgrade() {
        #expect(UpdateVersionPolicy.isUpgrade(from: "0.2.0", to: "0.3.0"))
        #expect(UpdateVersionPolicy.isUpgrade(from: "0.9.9", to: "0.10.0"))
        #expect(UpdateVersionPolicy.isUpgrade(from: "1.0", to: "1.0.1"))
        #expect(!UpdateVersionPolicy.isUpgrade(from: "0.3.0", to: "0.3.0"))
        #expect(!UpdateVersionPolicy.isUpgrade(from: "0.3.0", to: "0.3"))
        #expect(!UpdateVersionPolicy.isUpgrade(from: "0.10.0", to: "0.9.9"))
        #expect(!UpdateVersionPolicy.isUpgrade(from: "1.0.0", to: "0.99.99"))
    }

    @Test func anythingNotNumericIsRefused() {
        #expect(UpdateVersionPolicy.components("0.3.0") == [0, 3, 0])
        #expect(UpdateVersionPolicy.components("0.3.0-rc.1") == nil)
        #expect(UpdateVersionPolicy.components("") == nil)
        #expect(UpdateVersionPolicy.components("1..2") == nil)
        #expect(UpdateVersionPolicy.components("1.2.") == nil)
        #expect(UpdateVersionPolicy.components("+1.2") == nil)
        #expect(UpdateVersionPolicy.components("99999999999999999999") == nil)
        #expect(!UpdateVersionPolicy.isUpgrade(from: "0.3.0", to: "0.4.0b1"))
        #expect(!UpdateVersionPolicy.isUpgrade(from: "garbage", to: "0.4.0"))
    }
}

@Suite struct UpdateGuardTests {
    @Test func theDelegateRefusesAnythingNotStrictlyNewer() throws {
        try UpdateGuard.check(installed: "0.3.0", offered: "0.3.1")
        #expect(throws: UpdateGuard.Refusal.notNewer(installed: "0.3.0", offered: "0.3.0")) {
            try UpdateGuard.check(installed: "0.3.0", offered: "0.3.0")
        }
        #expect(throws: UpdateGuard.Refusal.notNewer(installed: "0.3.0", offered: "0.2.9")) {
            try UpdateGuard.check(installed: "0.3.0", offered: "0.2.9")
        }
        // A development build (CFBundleVersion "1") never takes a 0.x release.
        #expect(throws: UpdateGuard.Refusal.self) { try UpdateGuard.check(installed: "1", offered: "0.9.0") }
    }
}
