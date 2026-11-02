#if os(iOS)
import SwiftUI
import UIKit

/// The one fade under every header of the iPhone and iPad app: content scrolling up under the
/// status bar and the navigation bar (or a screen's own header, as the "+" sheet's title and search
/// field) fades out softly. The system's soft scroll edge effect blurs it, and a wash of the
/// screen's background, nearly opaque at the top edge, eases to nothing a little below the header.
/// One continuous fade, no band, no seam, the same on every screen.
///
/// The wash shows only once the content has moved under the header: a screen at rest is not dimmed
/// (an inline title sits right on top of its first card).
///
/// No material here: a material under the bar sits inside the scroll edge effect's own backdrop,
/// and the nested blur renders flat up to the bar's bottom, then drops to the material's real
/// opacity there (the hard edge). A plain color gradient blurs cleanly. The wash ends past the
/// header's bottom so no edge lines up with it. It lies over the content, under the bar's own
/// controls (the large title stays sharp), and never takes a touch.
struct HeaderFade: ViewModifier {
    /// The wash's color: the screen's background.
    let color: Color
    /// A screen's own header (the "+" sheet's title and search field): its height from the top of
    /// the scroll view. The wash covers it, then fades out below it. Nil for a navigation bar: the
    /// wash runs from the status bar to a little below the compact bar.
    let header: CGFloat?
    /// How far the content has gone under the header, in points.
    @State private var scrolled: CGFloat = 0

    @MainActor static var statusBarHeight: CGFloat {
        let scene = UIApplication.shared.connectedScenes.first { $0.activationState == .foregroundActive } as? UIWindowScene
        return scene?.keyWindow?.safeAreaInsets.top ?? 59
    }

    /// The compact navigation bar (about 52 pt) and the room the wash takes to fade out below it.
    static let barAndFade: CGFloat = 100
    /// Below a screen's own header, the points over which the wash fades out.
    static let headerFadeLength: CGFloat = 44
    /// Points of scrolling over which the wash comes in.
    static let ramp: CGFloat = 18

    /// Opacity along the wash, eased (smoothstep-like) so neither end shows a line.
    static let curve: [(location: Double, opacity: Double)] = [
        (0.00, 0.90), (0.20, 0.86), (0.38, 0.74), (0.52, 0.56),
        (0.66, 0.36), (0.78, 0.19), (0.89, 0.07), (1.00, 0.00),
    ]

    /// How much of the wash shows after `offset` points of scrolling: none at rest, all of it once
    /// the content has gone `ramp` points under the header.
    static func presence(scrolled offset: CGFloat) -> Double {
        Double(min(max(offset / ramp, 0), 1))
    }

    func body(content: Content) -> some View {
        let stops = Self.curve.map { Gradient.Stop(color: color.opacity($0.opacity), location: $0.location) }
        content
            .scrollEdgeEffectStyle(.soft, for: .top)
            .onScrollGeometryChange(for: CGFloat.self) { geometry in
                geometry.contentOffset.y + geometry.contentInsets.top
            } action: { _, offset in
                // Horizontal strips inside the screen (chips) report no vertical movement.
                if abs(offset - scrolled) > 0.5 { scrolled = offset }
            }
            .overlay(alignment: .top) {
                GeometryReader { _ in
                    wash(stops)
                        .ignoresSafeArea(edges: .top)
                        .opacity(Self.presence(scrolled: scrolled))
                        .animation(.easeOut(duration: 0.15), value: scrolled > 0)
                }
                .allowsHitTesting(false)
                .accessibilityHidden(true)
            }
    }

    @ViewBuilder private func wash(_ stops: [Gradient.Stop]) -> some View {
        if let header {
            // Under a header of its own the content must not show through the title or the field:
            // the wash is at its densest there, then fades out below it along the same curve.
            VStack(spacing: 0) {
                color.opacity(Self.curve[0].opacity).frame(height: header)
                LinearGradient(stops: stops, startPoint: .top, endPoint: .bottom)
                    .frame(height: Self.headerFadeLength)
            }
        } else {
            LinearGradient(stops: stops, startPoint: .top, endPoint: .bottom)
                .frame(height: Self.statusBarHeight + Self.barAndFade)
        }
    }
}

extension HeaderFade {
    /// The page color of the iPhone and iPad screens (the theme's token, light or dark).
    static var screenColor: Color { Theme.page }
}

extension View {
    /// The fade under a navigation bar (or under a screen's own `header`, its height in points from
    /// the top of the scroll view), the same on every iPhone and iPad screen. `color`: the screen's
    /// background.
    public func headerFade(color: Color? = nil, header: CGFloat? = nil) -> some View {
        modifier(HeaderFade(color: color ?? HeaderFade.screenColor, header: header))
    }
}
#endif
