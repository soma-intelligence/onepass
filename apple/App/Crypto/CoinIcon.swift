import SwiftUI

/// Round coin marks drawn in SwiftUI: a flat disc in the coin's color and a simple white glyph
/// (₿, the Ether diamond, three Solana bars, a dollar sign for the dollar stablecoins, a ticker
/// letter otherwise). Bundled code, nothing downloaded or hotlinked, no third-party artwork to
/// license (ruling CW4).
struct CoinIcon: View {
    let coin: String
    var symbol: String = ""
    var size: CGFloat = 40

    var body: some View {
        ZStack {
            Circle().fill(Self.color(coin))
            glyph
                .foregroundStyle(.white)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    @ViewBuilder private var glyph: some View {
        switch coin {
        case "bitcoin", "wrapped-bitcoin":
            Image(systemName: "bitcoinsign")
                .font(.system(size: size * 0.5, weight: .bold))
                .rotationEffect(.degrees(12))
        case "ethereum":
            EtherDiamond().frame(width: size * 0.34, height: size * 0.56)
        case "solana":
            SolanaBars().frame(width: size * 0.5, height: size * 0.4)
        case "tether", "usd-coin", "dai":
            Image(systemName: "dollarsign")
                .font(.system(size: size * 0.48, weight: .bold))
        case "chainlink":
            Image(systemName: "hexagon")
                .font(.system(size: size * 0.5, weight: .bold))
        case "uniswap":
            Text(verbatim: "U").font(.system(size: size * 0.46, weight: .heavy, design: .rounded))
        default:
            Text(verbatim: String(symbol.prefix(1)).uppercased())
                .font(.system(size: size * 0.44, weight: .bold, design: .rounded))
        }
    }

    /// Each coin's own color, muted a little so a list of them stays calm.
    static func color(_ coin: String) -> Color {
        switch coin {
        case "bitcoin": Color(red: 0.95, green: 0.58, blue: 0.10)
        case "wrapped-bitcoin": Color(red: 0.24, green: 0.23, blue: 0.30)
        case "ethereum": Color(red: 0.38, green: 0.42, blue: 0.80)
        case "solana": Color(red: 0.13, green: 0.12, blue: 0.20)
        case "tether": Color(red: 0.15, green: 0.63, blue: 0.48)
        case "usd-coin": Color(red: 0.16, green: 0.46, blue: 0.80)
        case "dai": Color(red: 0.93, green: 0.66, blue: 0.16)
        case "chainlink": Color(red: 0.17, green: 0.35, blue: 0.80)
        case "uniswap": Color(red: 0.92, green: 0.20, blue: 0.55)
        default:
            // A stable color from the id for market coins.
            Color(hue: Double(coin.unicodeScalars.reduce(0) { ($0 &* 31 &+ Int($1.value)) % 360 }) / 360,
                  saturation: 0.35, brightness: 0.55)
        }
    }
}

/// The two stacked facets of the Ether mark, flat.
private struct EtherDiamond: View {
    var body: some View {
        GeometryReader { g in
            let w = g.size.width, h = g.size.height
            Path { p in
                p.move(to: CGPoint(x: w / 2, y: 0))
                p.addLine(to: CGPoint(x: w, y: h * 0.52))
                p.addLine(to: CGPoint(x: w / 2, y: h * 0.68))
                p.addLine(to: CGPoint(x: 0, y: h * 0.52))
                p.closeSubpath()
            }
            .fill(.white)
            Path { p in
                p.move(to: CGPoint(x: 0, y: h * 0.6))
                p.addLine(to: CGPoint(x: w / 2, y: h * 0.76))
                p.addLine(to: CGPoint(x: w, y: h * 0.6))
                p.addLine(to: CGPoint(x: w / 2, y: h))
                p.closeSubpath()
            }
            .fill(.white.opacity(0.85))
        }
    }
}

/// Three slanted bars.
private struct SolanaBars: View {
    var body: some View {
        GeometryReader { g in
            let w = g.size.width, h = g.size.height
            let bar = h * 0.22, gap = (h - 3 * bar) / 2, slant = w * 0.18
            ForEach(0..<3, id: \.self) { i in
                let y = CGFloat(i) * (bar + gap)
                Path { p in
                    let leftward = i == 1
                    p.move(to: CGPoint(x: leftward ? 0 : slant, y: y))
                    p.addLine(to: CGPoint(x: leftward ? w - slant : w, y: y))
                    p.addLine(to: CGPoint(x: leftward ? w : w - slant, y: y + bar))
                    p.addLine(to: CGPoint(x: leftward ? slant : 0, y: y + bar))
                    p.closeSubpath()
                }
                .fill(.white)
            }
        }
    }
}
