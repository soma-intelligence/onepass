import SwiftUI
#if os(iOS)
import UIKit
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
