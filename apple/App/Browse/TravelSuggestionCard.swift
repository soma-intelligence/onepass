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
        switch model.travel.prompt {
        case .suggest(let reason, _):
            let text = Self.text(for: reason)
            card(
                title: text.title,
                detail: text.detail,
                symbol: text.symbol,
                error: Self.autoError(for: reason, message: model.travel.lastAutoError)
            ) {
                Button("app.yes") {
                    model.travel.answerYes()
                    model.travelSheet = .enter
                }
                .buttonStyle(.glassProminent)
                .accessibilityIdentifier("travel.suggest.yes")
                Button("travel.suggest.no") { withAnimation(.snappy) { model.travel.answerNo() } }
                    .buttonStyle(.glass)
                    .accessibilityIdentifier("travel.suggest.no")
                Button("app.later") { withAnimation(.snappy) { model.travel.answerNotNow() } }
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
                Button("app.later") { withAnimation(.snappy) { model.travel.dismissWelcome() } }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("travel.welcome.later")
            }
            .accessibilityIdentifier("travel.welcome")
        case .none, .autoEnter:
            // `.autoEnter`: AppModel enters Travel Mode at the unlock, the card has nothing to ask.
            EmptyView()
        }
    }

    /// The card's words follow why it appears. Airport and calendar reasons are not produced yet
    /// and speak like "away" until their own texts come.
    private static func text(for reason: TravelReason)
        -> (title: LocalizedStringKey, detail: LocalizedStringKey, symbol: String) {
        switch reason {
        case .tripStarting:
            ("travel.trip.title", "travel.trip.body", "airplane.departure")
        case .newTimeZone:
            ("travel.timezone.title", "travel.timezone.body", "clock.arrow.2.circlepath")
        case .away, .atAirport, .flightFound:
            ("travel.suggest.title", "travel.suggest.body", "airplane.departure")
        }
    }

    /// Why the automatic entry failed, only on the trip's own card.
    private static func autoError(for reason: TravelReason, message: String?) -> String? {
        guard case .tripStarting = reason, let message else { return nil }
        return String(localized: "travel.auto.failed \(message)")
    }

    private func card<Buttons: View>(
        title: LocalizedStringKey, detail: LocalizedStringKey, symbol: String, error: String? = nil,
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
            if let error {
                Text(error)
                    .font(compact ? .caption : .footnote)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("travel.suggest.error")
            }
            HStack(spacing: 8) { buttons() }
                .controlSize(.small)
                .font(.footnote.weight(.semibold))
        }
        .accessibilityElement(children: .contain)
    }
}
