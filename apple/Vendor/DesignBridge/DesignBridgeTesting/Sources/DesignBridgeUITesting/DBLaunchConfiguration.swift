import Foundation

// Platform neutral so the launch contract can be unit tested on macOS and read by app code.

/// Launch settings a UI test passes to the app.
///
/// System arguments (`-UIPreferredContentSizeCategoryName`, `-AppleLanguages`) are honoured by
/// iOS directly. The `-DB*` arguments are the DesignBridge contract the app reads at launch,
/// because colour scheme and Reduce Motion have no launch argument the system honours reliably.
public struct DBLaunchConfiguration: Sendable, Equatable {
    public enum Theme: String, Sendable, CaseIterable {
        case light, dark, system
    }

    public enum ContentSize: String, Sendable, CaseIterable {
        case xSmall, large, accessibility3, accessibility5

        /// The value of `-UIPreferredContentSizeCategoryName`.
        public var systemName: String {
            switch self {
            case .xSmall: "UICTContentSizeCategoryXS"
            case .large: "UICTContentSizeCategoryL"
            case .accessibility3: "UICTContentSizeCategoryAccessibilityXL"
            case .accessibility5: "UICTContentSizeCategoryAccessibilityXXXL"
            }
        }
    }

    public var theme: Theme
    public var contentSize: ContentSize
    public var reduceMotion: Bool
    /// A locale identifier such as `fr_FR`; nil keeps the simulator language.
    public var locale: String?
    /// Turns on the system double-length pseudo-language (`-NSDoubleLocalizedStrings YES`).
    public var doubleLengthStrings: Bool
    public var extraArguments: [String]
    public var environment: [String: String]

    public init(
        theme: Theme = .light,
        contentSize: ContentSize = .large,
        reduceMotion: Bool = false,
        locale: String? = nil,
        doubleLengthStrings: Bool = false,
        extraArguments: [String] = [],
        environment: [String: String] = [:]
    ) {
        self.theme = theme
        self.contentSize = contentSize
        self.reduceMotion = reduceMotion
        self.locale = locale
        self.doubleLengthStrings = doubleLengthStrings
        self.extraArguments = extraArguments
        self.environment = environment
    }

    /// Keys of the DesignBridge launch contract.
    public enum Key {
        public static let colorScheme = "-DBColorScheme"
        public static let dynamicTypeSize = "-DBDynamicTypeSize"
        public static let reduceMotion = "-DBReduceMotion"
        public static let uiTestingEnvironment = "DB_UI_TESTING"
    }

    public var launchArguments: [String] {
        var args: [String] = []
        args += [Key.colorScheme, theme.rawValue]
        args += [Key.dynamicTypeSize, contentSize.rawValue]
        args += ["-UIPreferredContentSizeCategoryName", contentSize.systemName]
        args += [Key.reduceMotion, reduceMotion ? "YES" : "NO"]
        args += ["-UIAccessibilityReduceMotionEnabled", reduceMotion ? "YES" : "NO"]
        if let locale {
            let language = locale.split(whereSeparator: { $0 == "_" || $0 == "-" }).first.map(String.init) ?? locale
            args += ["-AppleLanguages", "(\(language))", "-AppleLocale", locale]
        }
        if doubleLengthStrings { args += ["-NSDoubleLocalizedStrings", "YES"] }
        return args + extraArguments
    }

    /// Reads `DB_THEME`, `DB_CONTENT_SIZE`, `DB_REDUCE_MOTION` and `DB_LOCALE` from the test
    /// runner environment, so a CI matrix can drive every flow without code changes. Values
    /// not set (or not valid) keep the ones in `defaults`.
    public static func fromEnvironment(
        _ environment: [String: String] = ProcessInfo.processInfo.environment,
        defaults: DBLaunchConfiguration = .init()
    ) -> DBLaunchConfiguration {
        var c = defaults
        if let raw = environment["DB_THEME"], let theme = Theme(rawValue: raw.lowercased()) { c.theme = theme }
        if let raw = environment["DB_CONTENT_SIZE"], let size = ContentSize(rawValue: raw) { c.contentSize = size }
        if let raw = environment["DB_REDUCE_MOTION"] { c.reduceMotion = ["1", "yes", "true"].contains(raw.lowercased()) }
        if let raw = environment["DB_LOCALE"], !raw.isEmpty { c.locale = raw }
        return c
    }

    public var launchEnvironment: [String: String] {
        var env = environment
        env[Key.uiTestingEnvironment] = "1"
        return env
    }
}
