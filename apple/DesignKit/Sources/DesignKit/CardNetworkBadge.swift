import SwiftUI

/// Small rounded badge naming the network of a credit card (drawn simply, no official artwork).
public struct CardNetworkBadge: View {
    public enum CardNetwork: String, CaseIterable, Sendable {
        case visa, mastercard, amex, discover, cb, unionPay, jcb, unknown

        /// Network from the IIN prefix of a card number. Spaces and dashes are ignored. CB cards
        /// cannot be told apart by prefix alone (they are co-branded Visa or Mastercard), so `.cb`
        /// is never returned.
        public static func detect(number: String) -> CardNetwork {
            let digits = number.filter { $0.isASCII && $0.isNumber }
            func prefix(_ n: Int) -> Int? {
                digits.count >= n ? Int(digits.prefix(n)) : nil
            }
            if let p = prefix(2), p == 34 || p == 37 { return .amex }
            if let p = prefix(4), (3528...3589).contains(p) { return .jcb }
            if prefix(4) == 6011 || prefix(2) == 65 { return .discover }
            if let p = prefix(3), (644...649).contains(p) { return .discover }
            if prefix(2) == 62 { return .unionPay }
            if let p = prefix(2), (51...55).contains(p) { return .mastercard }
            if let p = prefix(4), (2221...2720).contains(p) { return .mastercard }
            if digits.first == "4" { return .visa }
            return .unknown
        }

        /// Name read by VoiceOver and shown in plain text.
        public var name: String {
            switch self {
            case .visa: "Visa"
            case .mastercard: "Mastercard"
            case .amex: "American Express"
            case .discover: "Discover"
            case .cb: "CB"
            case .unionPay: "UnionPay"
            case .jcb: "JCB"
            case .unknown: String(localized: "Carte bancaire", bundle: DesignKitStrings.bundle)
            }
        }
    }

    private let network: CardNetwork
    private let height: CGFloat

    public init(network: CardNetwork) {
        self.init(network: network, height: 20)
    }

    /// `height` in points; the badge is 1.55 times as wide.
    public init(network: CardNetwork, height: CGFloat) {
        self.network = network
        self.height = height
    }

    private var width: CGFloat { (height * 1.55).rounded() }
    private var corner: CGFloat { height * 0.22 }

    public var body: some View {
        let shape = RoundedRectangle(cornerRadius: corner, style: .continuous)
        ZStack {
            shape.fill(background)
            mark
        }
        .frame(width: width, height: height)
        .clipShape(shape)
        .overlay(shape.strokeBorder(Color.black.opacity(network.lightTile ? 0.12 : 0.06), lineWidth: 0.5))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: network.name))
    }

    private var background: AnyShapeStyle {
        switch network {
        case .visa: AnyShapeStyle(Color(hex: 0x1A1F71))
        case .mastercard, .discover: AnyShapeStyle(Color(hex: 0xF4F4F5))
        case .amex: AnyShapeStyle(Color(hex: 0x2E77BB))
        case .cb:
            AnyShapeStyle(
                LinearGradient(
                    colors: [Color(hex: 0x1E5BA8), Color(hex: 0x1D8A9A), Color(hex: 0x2BA84A)],
                    startPoint: .topLeading, endPoint: .bottomTrailing))
        case .unionPay:
            AnyShapeStyle(
                LinearGradient(
                    stops: [
                        .init(color: Color(hex: 0xD6262E), location: 0.33),
                        .init(color: Color(hex: 0x0B4A8B), location: 0.33),
                        .init(color: Color(hex: 0x0B4A8B), location: 0.66),
                        .init(color: Color(hex: 0x0D8A6A), location: 0.66),
                    ], startPoint: .leading, endPoint: .trailing))
        case .jcb:
            AnyShapeStyle(
                LinearGradient(
                    colors: [Color(hex: 0x1C4FA0), Color(hex: 0xC8102E), Color(hex: 0x14853B)],
                    startPoint: .leading, endPoint: .trailing))
        case .unknown: AnyShapeStyle(Color(hex: 0xE4E7EC))
        }
    }

    @ViewBuilder private var mark: some View {
        switch network {
        case .visa:
            word("VISA", size: 0.5, color: .white, italic: true, weight: .black, tracking: -0.02)
        case .mastercard:
            let d = height * 0.62
            ZStack {
                Circle().fill(Color(hex: 0xEB001B)).frame(width: d, height: d).offset(x: -d * 0.3)
                Circle().fill(Color(hex: 0xF79E1B)).frame(width: d, height: d).offset(x: d * 0.3)
                // The overlap, in the mix of both.
                Circle().fill(Color(hex: 0xFF5F00)).frame(width: d, height: d).offset(x: d * 0.3)
                    .mask(Circle().frame(width: d, height: d).offset(x: -d * 0.3))
            }
        case .amex:
            word("AMEX", size: 0.4, color: .white, italic: false, weight: .heavy, tracking: 0.02)
        case .discover:
            HStack(spacing: height * 0.04) {
                word("DISC", size: 0.3, color: Color(hex: 0x231F20), italic: false, weight: .heavy, tracking: 0)
                Circle().fill(Color(hex: 0xF58220)).frame(width: height * 0.3, height: height * 0.3)
            }
        case .cb:
            word("CB", size: 0.52, color: .white, italic: false, weight: .heavy, tracking: 0)
        case .unionPay:
            word("UP", size: 0.46, color: .white, italic: true, weight: .black, tracking: 0)
        case .jcb:
            word("JCB", size: 0.44, color: .white, italic: false, weight: .black, tracking: 0)
        case .unknown:
            Image(systemName: "creditcard.fill")
                .font(.system(size: height * 0.5, weight: .medium))
                .foregroundStyle(Color(hex: 0x667085))
        }
    }

    private func word(
        _ s: String, size: CGFloat, color: Color, italic: Bool, weight: Font.Weight, tracking: CGFloat
    ) -> some View {
        Text(verbatim: s)
            .font(.system(size: height * size, weight: weight, design: .default))
            .italic(italic)
            .tracking(height * tracking)
            .foregroundStyle(color)
            .lineLimit(1)
            .minimumScaleFactor(0.5)
            .padding(.horizontal, height * 0.12)
    }
}

extension CardNetworkBadge.CardNetwork {
    fileprivate var lightTile: Bool { self == .mastercard || self == .discover || self == .unknown }
}

#Preview("CardNetworkBadge") {
    HStack(spacing: 8) {
        ForEach(CardNetworkBadge.CardNetwork.allCases, id: \.self) { n in
            CardNetworkBadge(network: n, height: 24)
        }
    }
    .padding()
}
