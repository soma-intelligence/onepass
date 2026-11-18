import Foundation
import SwiftUI

/// The app side of the DesignBridgeTesting launch contract (`DBLaunchConfiguration`): colour
/// scheme, Dynamic Type size and Reduce Motion forced by a UI test or a capture script.
///
/// Sources, strongest first:
/// - launch arguments `-DBColorScheme light|dark|system`, `-DBDynamicTypeSize xSmall|large|...`,
///   `-DBReduceMotion YES|NO`;
/// - environment variables `DB_THEME`, `DB_CONTENT_SIZE`, `DB_REDUCE_MOTION` (the names the CI
///   matrix uses for the test runner, also accepted by the app for `simctl launch`).
///
/// Release builds ignore both: `current` is empty outside DEBUG.
public struct DBLaunchOverrides: Sendable, Equatable {
    public var colorScheme: ColorScheme?
    public var dynamicTypeSize: DynamicTypeSize?
    public var reduceMotion: Bool?

    public init(colorScheme: ColorScheme? = nil, dynamicTypeSize: DynamicTypeSize? = nil, reduceMotion: Bool? = nil) {
        self.colorScheme = colorScheme
        self.dynamicTypeSize = dynamicTypeSize
        self.reduceMotion = reduceMotion
    }

    public static let none = DBLaunchOverrides()

    public var isEmpty: Bool { self == .none }

    /// Keys of the contract, the same strings as `DBLaunchConfiguration.Key`.
    public enum Key {
        public static let colorScheme = "-DBColorScheme"
        public static let dynamicTypeSize = "-DBDynamicTypeSize"
        public static let reduceMotion = "-DBReduceMotion"
        public static let themeEnvironment = "DB_THEME"
        public static let contentSizeEnvironment = "DB_CONTENT_SIZE"
        public static let reduceMotionEnvironment = "DB_REDUCE_MOTION"
        /// The UIKit argument for the text size, honoured by the system itself.
        public static let systemContentSize = "-UIPreferredContentSizeCategoryName"
    }

    /// The overrides of this process: parsed once from its arguments and environment in DEBUG,
    /// always empty in release.
    public static let current: DBLaunchOverrides = {
        #if DEBUG
        let info = ProcessInfo.processInfo
        return parse(arguments: info.arguments, environment: info.environment)
        #else
        return .none
        #endif
    }()

    /// Pure parser, for tests. An argument wins over the environment variable of the same setting.
    /// Unknown values are ignored, so a typo never breaks a launch.
    public static func parse(arguments: [String], environment: [String: String]) -> DBLaunchOverrides {
        func argument(_ key: String) -> String? {
            guard let index = arguments.firstIndex(of: key), arguments.indices.contains(index + 1) else { return nil }
            return arguments[index + 1]
        }
        var result = DBLaunchOverrides()
        if let raw = argument(Key.colorScheme) ?? environment[Key.themeEnvironment] {
            result.colorScheme = colorScheme(raw)
        }
        // UIKit honours `-UIPreferredContentSizeCategoryName` (DBLaunchConfiguration passes it
        // too): pinning the size in SwiftUI as well would stop the text from following a size
        // change, which the accessibility audit's Dynamic Type check makes.
        if !arguments.contains(Key.systemContentSize),
           let raw = argument(Key.dynamicTypeSize) ?? environment[Key.contentSizeEnvironment] {
            result.dynamicTypeSize = dynamicTypeSize(raw)
        }
        if let raw = argument(Key.reduceMotion) ?? environment[Key.reduceMotionEnvironment] {
            result.reduceMotion = bool(raw)
        }
        return result
    }

    static func colorScheme(_ raw: String) -> ColorScheme? {
        switch raw.lowercased() {
        case "light": .light
        case "dark": .dark
        default: nil // "system" and anything else: follow the device.
        }
    }

    static func dynamicTypeSize(_ raw: String) -> DynamicTypeSize? {
        switch raw.lowercased() {
        case "xsmall": .xSmall
        case "small": .small
        case "medium": .medium
        case "large": .large
        case "xlarge": .xLarge
        case "xxlarge": .xxLarge
        case "xxxlarge": .xxxLarge
        case "accessibility1": .accessibility1
        case "accessibility2": .accessibility2
        case "accessibility3": .accessibility3
        case "accessibility4": .accessibility4
        case "accessibility5": .accessibility5
        default: nil
        }
    }

    static func bool(_ raw: String) -> Bool? {
        switch raw.lowercased() {
        case "1", "yes", "true": true
        case "0", "no", "false": false
        default: nil
        }
    }
}

public extension View {
    /// Applies `DBLaunchOverrides.current` (DEBUG only): put it once at the root, above
    /// `.dbToastHost()`, so every primitive below reads the forced colour scheme, text size and
    /// Reduce Motion. A no-op in release builds and when nothing was passed.
    func dbLaunchOverrides(_ overrides: DBLaunchOverrides = .current) -> some View {
        modifier(DBLaunchOverridesModifier(overrides: overrides))
    }
}

private struct DBLaunchOverridesModifier: ViewModifier {
    let overrides: DBLaunchOverrides

    func body(content: Content) -> some View {
        content
            .modifier(OptionalColorScheme(scheme: overrides.colorScheme))
            .modifier(OptionalTypeSize(size: overrides.dynamicTypeSize))
            .modifier(OptionalReduceMotion(reduceMotion: overrides.reduceMotion))
    }
}

private struct OptionalColorScheme: ViewModifier {
    let scheme: ColorScheme?
    func body(content: Content) -> some View {
        if let scheme { content.preferredColorScheme(scheme) } else { content }
    }
}

private struct OptionalTypeSize: ViewModifier {
    let size: DynamicTypeSize?
    func body(content: Content) -> some View {
        if let size { content.dynamicTypeSize(size) } else { content }
    }
}

private struct OptionalReduceMotion: ViewModifier {
    let reduceMotion: Bool?
    func body(content: Content) -> some View {
        // `accessibilityReduceMotion` is read only; its underscored twin is the settable storage.
        if let reduceMotion { content.environment(\._accessibilityReduceMotion, reduceMotion) } else { content }
    }
}
