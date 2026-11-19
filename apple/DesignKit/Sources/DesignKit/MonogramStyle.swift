import Foundation

import SwiftUI

/// Palette and letter rules for the monogram tile shown when an item has no icon.
public enum MonogramStyle {
    /// An sRGB color as 0 to 255 components.
    public struct RGB: Equatable, Sendable {
        public let red: Int
        public let green: Int
        public let blue: Int

        init(_ hex: UInt32) {
            red = Int((hex >> 16) & 0xFF)
            green = Int((hex >> 8) & 0xFF)
            blue = Int(hex & 0xFF)
        }

        var color: Color {
            Color(.sRGB, red: Double(red) / 255, green: Double(green) / 255, blue: Double(blue) / 255, opacity: 1)
        }
    }

    /// Twelve calm hues, each readable under white text (contrast of at least 3:1) in light and dark.
    public static let paletteRGB: [(light: RGB, dark: RGB)] = [
        (RGB(0x5856D6), RGB(0x6E6CE0)),  // indigo
        (RGB(0xAF52DE), RGB(0xB462E0)),  // purple
        (RGB(0xC2308A), RGB(0xCC4A9C)),  // magenta
        (RGB(0xD1344B), RGB(0xD9505F)),  // red
        (RGB(0xC4561A), RGB(0xCC6228)),  // orange
        (RGB(0xA66A00), RGB(0xB07400)),  // amber
        (RGB(0x5E8A00), RGB(0x6A9610)),  // lime
        (RGB(0x1F8A4C), RGB(0x2C9A5B)),  // green
        (RGB(0x0E8A7D), RGB(0x1A9A8D)),  // teal
        (RGB(0x0A84A8), RGB(0x1A92B5)),  // cyan
        (RGB(0x2F6FDB), RGB(0x4A82E2)),  // blue
        (RGB(0x6B5B95), RGB(0x7C6CA6)),  // slate violet
    ]

    public static let palette: [(light: Color, dark: Color)] = paletteRGB.map { ($0.light.color, $0.dark.color) }

    /// FNV-1a 32-bit over the UTF-8 bytes of the lowercased seed, modulo the palette size.
    public static func colorIndex(seed: String) -> Int {
        var hash: UInt32 = 2_166_136_261
        for byte in seed.lowercased().utf8 {
            hash ^= UInt32(byte)
            hash = hash &* 16_777_619
        }
        return Int(hash % 12)
    }

    /// The first letter or digit of the trimmed title, uppercased; else the first letter or digit
    /// of the domain; nil when neither has one.
    public static func letter(title: String, domain: String?) -> String? {
        if let first = title.trimmingCharacters(in: .whitespacesAndNewlines).first, isLetterOrDigit(first) {
            return first.uppercased()
        }
        if let found = domain?.first(where: isLetterOrDigit) {
            return found.uppercased()
        }
        return nil
    }

    private static func isLetterOrDigit(_ c: Character) -> Bool { c.isLetter || c.isNumber }
}
