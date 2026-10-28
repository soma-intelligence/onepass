import SwiftUI

/// Colored disc with the first letter of the vault name, or a squircle tile in the sidebar.
public struct VaultBadge: View {
    private let name: String
    private let colorName: String
    private let size: CGFloat
    private let tile: Bool

    /// `tile`: the sidebar's squircle with a gradient, like its other row tiles.
    public init(name: String, colorName: String, size: CGFloat = 24, tile: Bool = false) {
        self.name = name
        self.colorName = colorName
        self.size = size
        self.tile = tile
    }

    /// The vault colors, in display order (a rainbow, then the neutrals). The first seven are the
    /// original palette: vaults saved with them keep their exact color.
    public nonisolated static let colorNames = [
        "red", "orange", "amber", "yellow", "lime", "green", "mint", "teal", "cyan",
        "sky", "blue", "indigo", "purple", "pink", "rose", "brown", "graphite", "gray",
    ]

    public nonisolated static func color(named: String) -> Color {
        switch named {
        case "red": Color(hex: 0xE5484D)
        case "orange": Color(hex: 0xE08A00)
        case "amber": Color(hex: 0xF5A623)
        case "yellow": Color(hex: 0xE6C02E)
        case "lime": Color(hex: 0x8CBF26)
        case "green": Color(hex: 0x22A06B)
        case "mint": Color(hex: 0x2EC4A0)
        case "teal": Color(hex: 0x0E9F9F)
        case "cyan": Color(hex: 0x16A9D6)
        case "sky": Color(hex: 0x5AA9F5)
        case "blue": Color(hex: 0x2F80ED)
        case "indigo": Color(hex: 0x5B5BD6)
        case "purple": Color(hex: 0x7C3AED)
        case "pink": Color(hex: 0xDB2777)
        case "rose": Color(hex: 0xF0718F)
        case "brown": Color(hex: 0xA0703F)
        case "graphite": Color(hex: 0x3F4450)
        case "gray": Color(hex: 0x5B6472)
        default: Color(hex: 0x5B6472)
        }
    }

    nonisolated static func initial(of name: String) -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let first = trimmed.first else { return "?" }
        return String(first).uppercased()
    }

    public var body: some View {
        let color = Self.color(named: colorName)
        Group {
            if tile {
                RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
                    .fill(color.gradient)
                    .overlay {
                        RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
                            .strokeBorder(.white.opacity(0.18), lineWidth: 0.5)
                    }
            } else {
                Circle().fill(color)
            }
        }
            .frame(width: size, height: size)
            .overlay {
                Text(Self.initial(of: name))
                    .font(.system(size: size * 0.5, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
                    .minimumScaleFactor(0.5)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text(verbatim: "Coffre \(name)"))
    }
}

#Preview("VaultBadge") {
    HStack {
        ForEach(["blue", "teal", "orange", "green", "purple", "pink", "gray"], id: \.self) {
            VaultBadge(name: "Projet Atlas", colorName: $0)
        }
    }
    .padding()
}
