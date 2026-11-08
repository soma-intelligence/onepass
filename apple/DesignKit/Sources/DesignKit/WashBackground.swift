import SwiftUI

/// Fills a shape with a wash that fades in once, or with a flat color when Increase Contrast or
/// Reduce Transparency is on. Both settings are read from the environment, so a live change redraws.
private struct WashBackground<S: Shape, Style: ShapeStyle>: ViewModifier {
    let style: Style
    let flat: Color
    let shape: S

    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var appeared = false

    func body(content: Content) -> some View {
        let isFlat = Theme.Wash.isFlat(
            increaseContrast: contrast == .increased, reduceTransparency: reduceTransparency)
        content.background {
            if isFlat {
                shape.fill(flat)
            } else {
                shape.fill(style)
                    .opacity(appeared ? 1 : 0)
                    .onAppear {
                        if reduceMotion {
                            appeared = true
                        } else {
                            withAnimation(.easeOut(duration: 0.25)) { appeared = true }
                        }
                    }
            }
        }
    }
}

extension View {
    /// Draws `style` behind the view in `shape`, falling back to `flat` under Increase Contrast or
    /// Reduce Transparency.
    public func washBackground<S: Shape>(_ style: some ShapeStyle, flat: Color, in shape: S) -> some View {
        modifier(WashBackground(style: style, flat: flat, shape: shape))
    }
}
