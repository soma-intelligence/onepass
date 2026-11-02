import DesignKit
import SwiftUI
import VaultKit

/// "Tu voyages ?" (spec 2026-11-02, section 6.3): on Accueil (iPhone) and in the sidebar (iPad and
/// Mac) when `TravelDetection` finds the device far from its usual places. Oui opens the Travel Mode
/// confirmation, Non teaches the place, Plus tard stays quiet until home. With Travel Mode on and
/// the device home again: "De retour ?".
struct TravelSuggestionCard: View {
    @Environment(AppModel.self) private var model
    var compact = false

    var body: some View {
        switch model.travel.suggestion {
        case .suggest:
            card(
                title: "travel.suggest.title",
                detail: "travel.suggest.body",
                symbol: "airplane.departure"
            ) {
                Button("Oui") {
                    model.travel.answerYes()
                    model.travelSheet = .enter
                }
                .buttonStyle(.glassProminent)
                .accessibilityIdentifier("travel.suggest.yes")
                Button("travel.suggest.no") { withAnimation(.snappy) { model.travel.answerNo() } }
                    .buttonStyle(.glass)
                    .accessibilityIdentifier("travel.suggest.no")
                Button("Plus tard") { withAnimation(.snappy) { model.travel.answerNotNow() } }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("travel.suggest.later")
            }
            .accessibilityIdentifier("travel.suggest")
        case .welcomeBack:
            card(
                title: "travel.welcome.title",
                detail: "travel.welcome.body",
                symbol: "airplane.arrival"
            ) {
                Button("travel.welcome.turnOff") { model.travelSheet = .exit }
                    .buttonStyle(.glassProminent)
                    .accessibilityIdentifier("travel.welcome.exit")
                Button("Plus tard") { withAnimation(.snappy) { model.travel.dismissWelcome() } }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("travel.welcome.later")
            }
            .accessibilityIdentifier("travel.welcome")
        case .none:
            EmptyView()
        }
    }

    private func card<Buttons: View>(
        title: LocalizedStringKey, detail: LocalizedStringKey, symbol: String,
        @ViewBuilder buttons: () -> Buttons
    ) -> some View {
        VStack(alignment: .leading, spacing: compact ? 8 : 10) {
            HStack(alignment: .center, spacing: 10) {
                Image(systemName: symbol)
                    .font(compact ? .body : .title3)
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
                Text(title)
                    .font(compact ? .subheadline.weight(.semibold) : .headline)
                Spacer(minLength: 0)
            }
            Text(detail)
                .font(compact ? .caption : .footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) { buttons() }
                .controlSize(.small)
                .font(.footnote.weight(.semibold))
        }
        .accessibilityElement(children: .contain)
    }
}
