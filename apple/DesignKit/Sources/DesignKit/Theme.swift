import SwiftUI
#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

/// Accent and shared helpers. Everything else uses system colors so dark mode
/// and increased contrast come for free.
public enum Theme {
    /// Indigo of the approved mockup (#5856D6).
    public static let accent = Color(red: 0x58 / 255, green: 0x56 / 255, blue: 0xD6 / 255)

    /// The accent for small text (field and card labels): 4.5:1 or better on the background.
    /// iPhone and iPad follow the appearance (the accent itself on light backgrounds, lightened on
    /// dark ones); the Mac keeps the lightened accent of its dark glass.
    #if os(iOS)
    public static let readableAccent = Color(uiColor: UIColor { traits in
        traits.userInterfaceStyle == .dark
            ? UIColor(red: 0xA3 / 255, green: 0xA2 / 255, blue: 0xE8 / 255, alpha: 1)
            : UIColor(red: 0x58 / 255, green: 0x56 / 255, blue: 0xD6 / 255, alpha: 1)
    })
    #else
    public static let readableAccent = accent.mix(with: .white, by: 0.45)
    #endif

    // MARK: Surfaces (iPhone and iPad)

    // One set of surfaces for every screen, light and dark, so no view picks its own gray. They
    // follow the appearance the person chose (`Appearance`) through the window's trait.

    #if os(iOS)
    /// The page behind the cards: the grouped background (a soft gray in light, black in dark).
    public static let page = Color(uiColor: .systemGroupedBackground)
    /// A card, a grouped row, the account panel's rows: white in light, a raised gray in dark.
    public static let card = Color(uiColor: .secondarySystemGroupedBackground)
    #elseif os(macOS)
    public static let page = Color(nsColor: .windowBackgroundColor)
    public static let card = Color(nsColor: .controlBackgroundColor)
    #else
    public static let page = Color.clear
    public static let card = Color.primary.opacity(0.06)
    #endif

    /// The hairline around a card: visible on the light gray page, barely there in dark.
    public static let cardHairline = Color.primary.opacity(0.06)

    /// Deprecated alias of `Radius.card`, kept until the UI sweep removes its uses.
    public static let cardRadius: CGFloat = Radius.card
}

/// The appearance the person picked in Réglages > Général: follow the system, or keep OnePass
/// light or dark whatever the system does. Stored per device (a phone in dark mode and a Mac in
/// light mode is a normal mix), never synced.
public enum Appearance: String, CaseIterable, Identifiable, Sendable {
    case system, light, dark

    /// The defaults key of the choice.
    public static let storageKey = "onepass.appearance"

    public var id: String { rawValue }

    /// `nil` follows the system.
    public var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }

    /// Reads a stored value; anything unknown (or nothing) follows the system.
    public init(stored: String?) {
        self = stored.flatMap(Appearance.init(rawValue:)) ?? .system
    }

    #if os(iOS)
    /// The window override that applies the choice to a whole scene, sheets and popovers included
    /// (a SwiftUI `preferredColorScheme(nil)` does not always give the system appearance back).
    public var interfaceStyle: UIUserInterfaceStyle {
        switch self {
        case .system: .unspecified
        case .light: .light
        case .dark: .dark
        }
    }
    #endif
}

extension Color {
    /// `0xRRGGBB`.
    init(hex: UInt32) {
        self.init(
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255)
    }
}
