import SwiftUI

/// Round lock of the mockup: white disc, accent disc, light disc, keyhole.
/// Drawn from `Shape`s so it scales and needs no asset.
public struct AppGlyph: View {
    private let size: CGFloat

    public init(size: CGFloat) { self.size = size }

    public var body: some View {
        ZStack {
            Circle().fill(Color.white)
                .shadow(color: .black.opacity(0.25), radius: size * 0.06, y: size * 0.06)
            Circle().fill(Theme.accent).frame(width: size * 84 / 104, height: size * 84 / 104)
            Circle().fill(Color(red: 0xF4 / 255, green: 0xF4 / 255, blue: 0xF8 / 255))
                .frame(width: size * 60 / 104, height: size * 60 / 104)
            Keyhole()
                .stroke(
                    Color(red: 0x1D / 255, green: 0x1D / 255, blue: 0x2B / 255),
                    style: StrokeStyle(lineWidth: size * 0.0144, lineCap: .butt)
                )
                .frame(width: size * 30 / 104, height: size * 30 / 104)
        }
        .frame(width: size, height: size)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("OnePass"))
        .accessibilityAddTraits(.isImage)
    }

    /// Mockup keyhole on a 12 x 12 grid: circle (6, 4.4) r 1.9, stem and notch.
    struct Keyhole: Shape {
        func path(in rect: CGRect) -> Path {
            let u = min(rect.width, rect.height) / 12
            func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
                CGPoint(x: rect.minX + x * u, y: rect.minY + y * u)
            }
            var path = Path()
            path.addEllipse(in: CGRect(origin: p(6 - 1.9, 4.4 - 1.9), size: CGSize(width: 3.8 * u, height: 3.8 * u)))
            path.move(to: p(6, 6.3))
            path.addLine(to: p(6, 9.7))
            path.move(to: p(6, 8.2))
            path.addLine(to: p(7.3, 8.2))
            return path
        }
    }
}

#Preview("AppGlyph") {
    HStack(spacing: 20) {
        AppGlyph(size: 104)
        AppGlyph(size: 48)
    }
    .padding(24)
    .background(Theme.accent.opacity(0.3))
}
