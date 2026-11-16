#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Accueil in the RX look (Penpot "iPhone · Home"): the photo hero becomes a rounded banner at
/// the top of the page (the tab keeps its navigation bar, search and options): the security score
/// over the photo with its status pill, then four quick actions on glass (new item, generate,
/// Watchtower, all items). The cards below are the classic ones in RX cards.
struct RXHomeHero: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openPhoneTab) private var openTab
    let itemCount: Int

    private typealias RX = Theme.RX

    var body: some View {
        let score = model.watchtower.report.map { Int($0.score) }
        VStack(spacing: RX.Space.xl) {
            VStack(spacing: 6) {
                Text("rx.home.scoreLabel \(itemCount)")
                    .rxFont(.calloutMedium)
                    .foregroundStyle(.white.opacity(0.8))
                HStack(alignment: .lastTextBaseline, spacing: RX.Space.xs) {
                    Text(score.map(String.init) ?? "–")
                        .font(.system(size: 64, weight: .bold))
                        .tracking(-2.5)
                        .monospacedDigit()
                        .contentTransition(.numericText())
                    Text(verbatim: "/100")
                        .rxFont(.title)
                        .opacity(0.7)
                }
                .foregroundStyle(.white)
                if let score {
                    HStack(spacing: 6) {
                        Image(systemName: "checkmark.seal.fill")
                            .foregroundStyle(ScoreGauge.color(score))
                        Text(ScoreGauge.label(score))
                            .rxFont(.footnoteBold)
                            .foregroundStyle(.white)
                    }
                    .padding(.horizontal, RX.Space.m)
                    .frame(height: 30)
                    .background(.white.opacity(0.18), in: Capsule())
                    .background(.ultraThinMaterial.opacity(0.6), in: Capsule())
                    .environment(\.colorScheme, .dark)
                }
            }
            .accessibilityElement(children: .combine)
            .onTapGesture { openTab(.watchtower) }
            QuickActionRow {
                Button { model.showNewItemPicker = true } label: {
                    QuickActionLabel(Text("Nouvel élément"), systemImage: "plus", onPhoto: true)
                }
                .accessibilityIdentifier("rx.home.newItem")
                Button { model.showGenerator = true } label: {
                    QuickActionLabel(Text("Générer"), systemImage: "key.horizontal.fill", onPhoto: true)
                }
                .accessibilityIdentifier("rx.home.generate")
                Button { openTab(.watchtower) } label: {
                    QuickActionLabel(Text(verbatim: "Watchtower"), systemImage: "checkmark.shield.fill", onPhoto: true)
                }
                .accessibilityIdentifier("rx.home.watchtower")
                NavigationLink(value: PhoneRoute.list(.all)) {
                    QuickActionLabel(Text("rx.home.allItems"), systemImage: "square.grid.2x2.fill", onPhoto: true)
                }
                .accessibilityIdentifier("home.all")
            }
            .buttonStyle(PressableButtonStyle())
        }
        .padding(.vertical, RX.Space.xl)
        .padding(.horizontal, RX.Space.s)
        .frame(maxWidth: .infinity)
        .background {
            ZStack {
                Image("rx-hero")
                    .resizable()
                    .scaledToFill()
                LinearGradient(
                    stops: [
                        .init(color: .black.opacity(0.25), location: 0), .init(color: .black.opacity(0.05), location: 0.55),
                        .init(color: .black.opacity(0.55), location: 1),
                    ],
                    startPoint: .top, endPoint: .bottom)
            }
            .accessibilityHidden(true)
        }
        .clipShape(RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous))
        // The score comes from the Watchtower report: computed here too when the tab was not opened.
        .task(id: model.session.summariesRevision) { model.watchtower.refreshIfNeeded(model.session) }
    }
}
#endif
