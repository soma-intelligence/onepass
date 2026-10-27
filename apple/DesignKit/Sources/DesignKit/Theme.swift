import SwiftUI

/// Accent and shared helpers. Everything else uses system colors so dark mode
/// and increased contrast come for free.
public enum Theme {
    /// Indigo of the approved mockup (#5856D6).
    public static let accent = Color(red: 0x58 / 255, green: 0x56 / 255, blue: 0xD6 / 255)
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
