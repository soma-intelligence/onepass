import DesignKit
import SwiftUI

/// The hero art of each RX screen: one asset name per screen, so swapping a picture is one line.
enum RXHero {
    static let home = "rx-hero-home"
    static let watchtower = "rx-hero-watch"
    static let settings = "rx-hero-settings"
    static let item = "rx-hero-item"
}

/// A soft, fixed backdrop at the top of an RX page (Watchtower, an item): the screen's art fading
/// into the page colour, lighter in the light appearance so dark text keeps its contrast.
struct RXBackdrop: View {
    let name: String
    var height: CGFloat = 360
    var lightOpacity: Double = 0.45
    var darkOpacity: Double = 0.8
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        ZStack(alignment: .top) {
            Theme.RX.Palette.pageBackground.color
            Image(name)
                .resizable()
                .scaledToFill()
                .frame(height: height)
                .frame(maxWidth: .infinity)
                .clipped()
                .mask(LinearGradient(colors: [.black, .black.opacity(0.6), .clear], startPoint: .top, endPoint: .bottom))
                .opacity(colorScheme == .dark ? darkOpacity : lightOpacity)
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}
