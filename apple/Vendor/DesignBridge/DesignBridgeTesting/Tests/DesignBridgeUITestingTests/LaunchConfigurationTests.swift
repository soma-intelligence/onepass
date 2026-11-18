import Testing
@testable import DesignBridgeUITesting

@Suite("Launch configuration")
struct LaunchConfigurationTests {
    func value(after flag: String, in args: [String]) -> String? {
        guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
        return args[i + 1]
    }

    @Test func defaultsAreLightLargeMotionOn() {
        let args = DBLaunchConfiguration().launchArguments
        #expect(value(after: "-DBColorScheme", in: args) == "light")
        #expect(value(after: "-UIPreferredContentSizeCategoryName", in: args) == "UICTContentSizeCategoryL")
        #expect(value(after: "-DBReduceMotion", in: args) == "NO")
        #expect(!args.contains("-AppleLanguages"))
    }

    @Test func darkAx5ReduceMotionFrench() {
        let c = DBLaunchConfiguration(theme: .dark, contentSize: .accessibility5, reduceMotion: true, locale: "fr_FR")
        let args = c.launchArguments
        #expect(value(after: "-DBColorScheme", in: args) == "dark")
        #expect(value(after: "-DBDynamicTypeSize", in: args) == "accessibility5")
        #expect(value(after: "-UIPreferredContentSizeCategoryName", in: args) == "UICTContentSizeCategoryAccessibilityXXXL")
        #expect(value(after: "-DBReduceMotion", in: args) == "YES")
        #expect(value(after: "-UIAccessibilityReduceMotionEnabled", in: args) == "YES")
        #expect(value(after: "-AppleLanguages", in: args) == "(fr)")
        #expect(value(after: "-AppleLocale", in: args) == "fr_FR")
    }

    @Test(arguments: DBLaunchConfiguration.ContentSize.allCases)
    func everyContentSizeHasASystemName(size: DBLaunchConfiguration.ContentSize) {
        #expect(size.systemName.hasPrefix("UICTContentSizeCategory"))
    }

    @Test func environmentFlagsUITesting() {
        let env = DBLaunchConfiguration(environment: ["API": "stub"]).launchEnvironment
        #expect(env["DB_UI_TESTING"] == "1")
        #expect(env["API"] == "stub")
    }

    @Test func extrasComeLast() {
        let args = DBLaunchConfiguration(doubleLengthStrings: true, extraArguments: ["-Seed", "1"]).launchArguments
        #expect(args.suffix(2) == ["-Seed", "1"])
        #expect(value(after: "-NSDoubleLocalizedStrings", in: args) == "YES")
    }

    @Test func readsTheRunnerEnvironment() {
        let c = DBLaunchConfiguration.fromEnvironment([
            "DB_THEME": "Dark", "DB_CONTENT_SIZE": "accessibility5", "DB_REDUCE_MOTION": "1", "DB_LOCALE": "fr_FR",
        ])
        #expect(c.theme == .dark)
        #expect(c.contentSize == .accessibility5)
        #expect(c.reduceMotion)
        #expect(c.locale == "fr_FR")
    }

    @Test func invalidEnvironmentKeepsDefaults() {
        let defaults = DBLaunchConfiguration(theme: .light, contentSize: .accessibility3)
        let c = DBLaunchConfiguration.fromEnvironment(["DB_THEME": "purple", "DB_CONTENT_SIZE": "huge"], defaults: defaults)
        #expect(c == defaults)
    }
}
