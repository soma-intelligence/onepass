import DesignKit
import SwiftUI

/// The hero art of each RX screen: one asset name per screen, so swapping a picture is one line.
enum RXHero {
    static let home = "rx-hero-home"
    static let watchtower = "rx-hero-watch"
    static let settings = "rx-hero-settings"
    static let item = "rx-hero-item"
}

/// A soft backdrop at the top of an RX page (Watchtower, an item, the profile): the screen's art
/// fading into the page colour, lighter in the light appearance so dark text keeps its contrast.
/// It moves with the page (`scroll` is how far the page has scrolled) and stretches down when the
/// page is pulled past its top, so the content never slides over a still picture.
struct RXBackdrop: View {
    let name: String
    var height: CGFloat = 360
    var lightOpacity: Double = 0.45
    var darkOpacity: Double = 0.8
    var scroll: CGFloat = 0
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        ZStack(alignment: .top) {
            Theme.RX.Palette.pageBackground.color
            Image(name)
                .resizable()
                .scaledToFill()
                .frame(height: height + max(0, -scroll))
                .frame(maxWidth: .infinity)
                .clipped()
                .mask(LinearGradient(colors: [.black, .black.opacity(0.6), .clear], startPoint: .top, endPoint: .bottom))
                .opacity(colorScheme == .dark ? darkOpacity : lightOpacity)
                .offset(y: -max(0, scroll))
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}

/// Puts an `RXBackdrop` behind a scroll view and keeps it moving with the scroll. The offset
/// lives here, so a scroll only redraws the backdrop, never the page.
struct RXScrollingBackdrop: ViewModifier {
    let name: String
    var height: CGFloat = 360
    var lightOpacity: Double = 0.45
    var darkOpacity: Double = 0.8
    let active: Bool
    @State private var scroll: CGFloat = 0

    func body(content: Content) -> some View {
        content
            .onScrollGeometryChange(for: CGFloat.self) { $0.contentOffset.y + $0.contentInsets.top } action: { _, new in
                if active { scroll = new }
            }
            .background(alignment: .top) {
                if active {
                    RXBackdrop(name: name, height: height, lightOpacity: lightOpacity, darkOpacity: darkOpacity, scroll: scroll)
                }
            }
    }
}
