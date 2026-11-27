import SwiftUI
import Testing
@testable import DesignBridgeKit

@Suite("Launch contract (DesignBridgeTesting DBLaunchConfiguration)")
struct LaunchOverridesTests {
    @Test func readsTheTestingArguments() {
        // The exact arguments DBLaunchConfiguration(theme: .dark, contentSize: .accessibility5,
        // reduceMotion: true).launchArguments produces.
        let arguments = [
            "/path/Kelid", "-DBColorScheme", "dark", "-DBDynamicTypeSize", "accessibility5",
            "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL",
            "-DBReduceMotion", "YES", "-UIAccessibilityReduceMotionEnabled", "YES",
        ]
        let overrides = DBLaunchOverrides.parse(arguments: arguments, environment: [:])
        // The size is left to UIKit, which honours its own argument; SwiftUI does not pin it.
        #expect(overrides == DBLaunchOverrides(colorScheme: .dark, dynamicTypeSize: nil, reduceMotion: true))
    }

    @Test func pinsTheSizeWithoutTheSystemArgument() {
        let overrides = DBLaunchOverrides.parse(
            arguments: ["/path/Kelid", "-DBDynamicTypeSize", "accessibility5"], environment: [:])
        #expect(overrides.dynamicTypeSize == .accessibility5)
    }

    @Test func readsTheEnvironmentWhenNoArgument() {
        let overrides = DBLaunchOverrides.parse(
            arguments: ["/path/Kelid"],
            environment: ["DB_THEME": "light", "DB_CONTENT_SIZE": "xSmall", "DB_REDUCE_MOTION": "0"])
        #expect(overrides == DBLaunchOverrides(colorScheme: .light, dynamicTypeSize: .xSmall, reduceMotion: false))
    }

    @Test func argumentBeatsEnvironment() {
        let overrides = DBLaunchOverrides.parse(
            arguments: ["-DBColorScheme", "dark"], environment: ["DB_THEME": "light"])
        #expect(overrides.colorScheme == .dark)
    }

    @Test func unknownOrSystemValuesAreIgnored() {
        let overrides = DBLaunchOverrides.parse(
            arguments: ["-DBColorScheme", "system", "-DBDynamicTypeSize", "huge", "-DBReduceMotion", "maybe"],
            environment: [:])
        #expect(overrides.isEmpty)
    }

    @Test func aTrailingKeyWithoutValueIsIgnored() {
        #expect(DBLaunchOverrides.parse(arguments: ["-DBColorScheme"], environment: [:]).isEmpty)
    }

    @Test(arguments: ["xSmall", "large", "accessibility3", "accessibility5"])
    func everyMatrixSizeParses(raw: String) {
        #expect(DBLaunchOverrides.dynamicTypeSize(raw) != nil)
    }
}

@Suite("Toast contract")
struct ToastContractTests {
    @Test func identifierMatchesTheUITestBase() {
        #expect(DBToast.accessibilityIdentifier == "db.toast")
    }
}

@Suite("Penpot registry")
struct PenpotRegistryTests {
    private struct Sample: PenpotMapped {
        static let penpot = PenpotComponent(path: "Row/Menu", props: ["title": .text("Title"), "icon": .swap("Icon")])
    }

    @Test func mappingIsPlainData() {
        #expect(Sample.penpot.path == "Row/Menu")
        #expect(Sample.penpot.props["title"] == .text("Title"))
        #expect(PenpotComponent(path: "Disc").props.isEmpty)
    }
}

@Suite("Kit strings")
struct KitStringsTests {
    @Test func shipsTheFourLanguages() {
        let languages = Set(Bundle.module.localizations)
        #expect(languages.isSuperset(of: ["en", "fr", "es", "it"]))
    }

    @Test func englishDefaults() {
        #expect(!DBStrings.retry.isEmpty)
        #expect(DBLoadError.offline.title == DBStrings.offlineTitle)
    }
}
