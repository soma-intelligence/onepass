import SwiftUI

/// Colored disc with the first letter of the vault name.
public struct VaultBadge: View {
    private let name: String
    private let colorName: String
    private let size: CGFloat

    public init(name: String, colorName: String, size: CGFloat = 24) {
        self.name = name
        self.colorName = colorName
        self.size = size
    }

    /// The seven vault colors a vault can take, in display order.
    public nonisolated static let colorNames = ["blue", "teal", "orange", "green", "purple", "pink", "gray"]

    public nonisolated static func color(named: String) -> Color {
        switch named {
        case "blue": Color(hex: 0x2F80ED)
        case "teal": Color(hex: 0x0E9F9F)
        case "orange": Color(hex: 0xE08A00)
        case "green": Color(hex: 0x22A06B)
        case "purple": Color(hex: 0x7C3AED)
        case "pink": Color(hex: 0xDB2777)
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
        Circle()
            .fill(Self.color(named: colorName))
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
