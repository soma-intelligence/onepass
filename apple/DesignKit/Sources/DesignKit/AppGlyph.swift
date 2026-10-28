import SwiftUI

/// The OnePass mark as the app icon draws it: an indigo tile with the Lattice,
/// two columns of dots and one bar where the third would be.
/// Drawn from `Shape`s so it scales and needs no asset. Geometry matches
/// `docs/assets/brand/render.mjs`.
public struct AppGlyph: View {
    private let size: CGFloat

    public init(size: CGFloat) { self.size = size }

    public var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.225, style: .continuous)
                .fill(
                    LinearGradient(
                        stops: [
                            .init(color: Color(red: 0x6E / 255, green: 0x6C / 255, blue: 0xF0 / 255), location: 0),
                            .init(color: Theme.accent, location: 0.45),
                            .init(color: Color(red: 0x3F / 255, green: 0x3D / 255, blue: 0xB8 / 255), location: 1),
                        ],
                        startPoint: UnitPoint(x: 0.33, y: 0),
                        endPoint: UnitPoint(x: 0.67, y: 1)
                    )
                )
                .shadow(color: Color(red: 0x1B / 255, green: 0x1A / 255, blue: 0x4A / 255).opacity(0.25),
                        radius: size * 0.06, y: size * 0.05)
            Lattice.Dots().fill(Color.white.opacity(0.55))
                .frame(width: size * 0.6, height: size * 0.6)
            Lattice.Bar().fill(Color.white)
                .frame(width: size * 0.6, height: size * 0.6)
        }
        .frame(width: size, height: size)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("OnePass"))
        .accessibilityAddTraits(.isImage)
    }

    /// The mark on a 100 x 100 grid: dots r 9 at x 23.5 / 49.5, y 24 / 50 / 76,
    /// bar 18 x 70 at (67.5, 15).
    enum Lattice {
        struct Dots: Shape {
            func path(in rect: CGRect) -> Path {
                let u = min(rect.width, rect.height) / 100
                var path = Path()
                for cx in [23.5, 49.5] as [CGFloat] {
                    for cy in [24, 50, 76] as [CGFloat] {
                        path.addEllipse(in: CGRect(x: rect.minX + (cx - 9) * u, y: rect.minY + (cy - 9) * u,
                                                   width: 18 * u, height: 18 * u))
                    }
                }
                return path
            }
        }

        struct Bar: Shape {
            func path(in rect: CGRect) -> Path {
                let u = min(rect.width, rect.height) / 100
                let bar = CGRect(x: rect.minX + 67.5 * u, y: rect.minY + 15 * u, width: 18 * u, height: 70 * u)
                return Path(roundedRect: bar, cornerRadius: 9 * u)
            }
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
