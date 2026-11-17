#if os(iOS)
import DesignBridgeSnapshots
import DesignKit
import SnapshotTesting
import SwiftUI
import Testing

/// The RX components on the DesignBridge smoke matrix (iPhone 17 Pro, light and dark, default
/// and AX5 text, English and pseudo-locale): no clipped text, no overlap, in both appearances.
/// Fixture words are fictional and go through the pseudo-locale. iOS simulator only:
/// `xcodebuild test -scheme DesignKit -destination 'platform=iOS Simulator,...'`. A missing
/// reference is recorded on the first run (the test then fails once, as swift-snapshot-testing
/// does), and compared after that.
@MainActor
@Suite(.snapshots(record: .missing))
struct RXSnapshotTests {
    private typealias RX = Theme.RX

    private struct Favorite: Identifiable {
        let id: String
        let title: String
        let color: Color
    }

    private static let favorites = [
        Favorite(id: "forge", title: "Forge Atlas", color: RX.Hue.violet),
        Favorite(id: "mail", title: "Courrier Exemple", color: RX.Hue.orange),
        Favorite(id: "bank", title: "Banque Exemple", color: RX.Hue.teal),
        Favorite(id: "train", title: "Rail Exemple", color: RX.Hue.violet),
    ]

    /// A page of the RX look holding `content`, on the page background.
    private func page<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        ScrollView {
            VStack(spacing: RX.Space.l) { content() }
                .padding(RX.Space.l)
        }
        .background(RX.Palette.pageBackground.color)
    }

    @Test func codeCard() {
        snapshotMatrix(of: { variant in
            page {
                RXCard {
                    RXCodeCard(
                        label: Text(verbatim: variant.locale.text("Verification code")),
                        code: "482913", remaining: 18, fraction: 0.6)
                }
            }
        }, name: "codeCard", matrix: .smoke)
    }

    @Test func rows() {
        snapshotMatrix(of: { variant in
            page {
                RXCard {
                    RXCardHeader(Text(verbatim: variant.locale.text("Vaults")))
                    RXItemRow(
                        title: Text(verbatim: variant.locale.text("Personal")),
                        subtitle: Text(verbatim: variant.locale.text("12 items")), count: 12, chevron: true
                    ) {
                        ColorDisc(systemImage: "person.fill", color: RX.Hue.violet)
                    }
                    RXItemRow(
                        title: Text(verbatim: variant.locale.text("Forge Atlas")),
                        subtitle: Text(verbatim: variant.locale.text("camille.durand@exemple.fr")),
                        value: Text(verbatim: variant.locale.text("2 min"))
                    ) {
                        ColorDisc(systemImage: "key.fill", color: RX.Hue.orange)
                    }
                }
                RXCard {
                    RXCardHeader(Text(verbatim: variant.locale.text("Recents")))
                    RXCardMessage(Text(verbatim: variant.locale.text("Items you use appear here.")))
                }
            }
        }, name: "rows", matrix: .smoke)
    }

    @Test func statTiles() {
        snapshotMatrix(of: { variant in
            page {
                HStack(alignment: .top, spacing: RX.Space.m) {
                    RXStatTile(value: 3, label: Text(verbatim: variant.locale.text("Weak")),
                               systemImage: "lock.fill", color: RX.Hue.orange)
                    RXStatTile(value: 12, label: Text(verbatim: variant.locale.text("Reused")),
                               systemImage: "square.on.square.fill", color: RX.Hue.violet)
                    RXStatTile(value: 1, label: Text(verbatim: variant.locale.text("Two-factor")),
                               systemImage: "checkmark.shield.fill", color: RX.Hue.teal)
                }
            }
        }, name: "statTiles", matrix: .smoke)
    }

    @Test func favoritesCarousel() {
        snapshotMatrix(of: { variant in
            page {
                RXCard {
                    RXCardHeader(Text(verbatim: variant.locale.text("Favorites")))
                    RXCarousel(nil, items: Self.favorites, spacing: RX.Space.s, inset: RX.Space.l) { favorite in
                        RXFavoriteTile(title: Text(verbatim: variant.locale.text(favorite.title))) {
                            ColorDisc(systemImage: "star.fill", color: favorite.color,
                                         diameter: RX.Metrics.favoriteLogo)
                        }
                    }
                    .padding(.bottom, RX.Space.m)
                }
            }
        }, name: "favoritesCarousel", matrix: .smoke)
    }
}
#endif
