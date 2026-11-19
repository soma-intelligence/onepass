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

    /// The narrowest iPhone the app supports (SE, 375 x 667 pt @2x): the smoke matrix on it.
    private static let narrow = SnapshotMatrix.smoke.with(devices: [
        SnapshotDevice(
            id: "iPhoneSE", size: CGSize(width: 375, height: 667), safeArea: .init(top: 20, bottom: 0), scale: 2,
            idiom: .phone, horizontalSizeClass: .compact)
    ])

    /// A dark photo stand-in: a fixed gradient drawn as an image, so the cells do not depend on an
    /// asset.
    private static let photo = Image(size: CGSize(width: 40, height: 80)) { context in
        context.fill(
            Path(CGRect(x: 0, y: 0, width: 40, height: 80)),
            with: .linearGradient(
                Gradient(colors: [Color(red: 0.16, green: 0.2, blue: 0.3), Color(red: 0.4, green: 0.32, blue: 0.42)]),
                startPoint: .zero, endPoint: CGPoint(x: 0, y: 80)))
    }

    /// The Plus plan card of Settings, in its Reduce Transparency look (the flat dark panel), not
    /// its default glass. Why: this bundle is a SwiftPM test target with no host app, so there is
    /// no UIApplication, no window scene and no key window; native Liquid Glass is drawn by the
    /// render server only on screen, and both `layer.render(in:)` and `drawHierarchy` in a bare
    /// UIWindow give an opaque white panel with the white words invisible (tried 2026-11-16).
    /// The flat panel shares everything else with the glass card (text, line limits, art crop,
    /// perk discs, AX5 layout), so these cells guard clipping and overlap at large type; the glass
    /// itself is checked by eye on device. `_accessibilityReduceTransparency` is the settable
    /// twin of the read-only `accessibilityReduceTransparency`, the value PlanCard reads.
    @Test func planCardReduceTransparency() {
        snapshotMatrix(of: { variant in
            page {
                PlanCard(
                    title: Text(verbatim: "Plus"),
                    subtitle: Text(verbatim: variant.locale.text("No subscription. View the benefits")),
                    art: Self.photo,
                    perks: ["key.fill", "person.3.fill", "airplane", "chevron.right"])
            }
            .environment(\._accessibilityReduceTransparency, true)
        }, name: "planCard-reduceTransparency", matrix: Self.narrow)
    }

    @Test func perkTile() {
        snapshotMatrix(of: { variant in
            page {
                PerkTile(
                    title: Text(verbatim: variant.locale.text("Family vaults")),
                    subtitle: Text(verbatim: variant.locale.text("Share with the people at home")),
                    systemImage: "person.3.fill", art: Self.photo)
                    .frame(width: 280)
            }
        }, name: "perkTile", matrix: Self.narrow)
    }

    @Test func heroPage() {
        snapshotMatrix(of: { variant in
            RXHeroPage(photo: Self.photo) {
                VStack(spacing: RX.Space.s) {
                    Text(verbatim: variant.locale.text("Camille Durand"))
                        .rxFont(.title)
                        .foregroundStyle(.white)
                    Text(verbatim: variant.locale.text("Personal device"))
                        .rxFont(.callout)
                        .foregroundStyle(.white)
                        .rxOnPhotoSecondary()
                }
                .padding(.vertical, RX.Space.xl)
            } sheet: {
                RXCard {
                    RXMenuRow(Text(verbatim: variant.locale.text("General")), systemImage: "gearshape.fill")
                    RXMenuRow(Text(verbatim: variant.locale.text("Lock")), systemImage: "lock.fill", chevron: false)
                }
            }
        }, name: "heroPage", matrix: Self.narrow)
    }
}
#endif
