import DesignKit
import SwiftUI

/// Three short cards before the welcome screen, shown once on a first launch: what OnePass does,
/// who holds the key, where it works. Plain words only; the cryptography stays in Settings.
struct OnboardingIntro: View {
    /// Called on "Passer" and on the last card's button.
    let finish: () -> Void

    @State private var page = 0
    @State private var forward = true
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private struct Card {
        let symbol: String
        let title: LocalizedStringResource
        let body: LocalizedStringResource
    }

    private let cards: [Card] = [
        Card(symbol: "key.horizontal.fill", title: "onboarding.intro.oneplace.title",
             body: "onboarding.intro.oneplace.body"),
        Card(symbol: "lock.fill", title: "onboarding.intro.yourkey.title",
             body: "onboarding.intro.yourkey.body"),
        Card(symbol: "macbook.and.iphone", title: "onboarding.intro.everywhere.title",
             body: "onboarding.intro.everywhere.body"),
    ]

    private var isLast: Bool { page == cards.count - 1 }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Spacer()
                if !isLast {
                    Button("onboarding.intro.skip") { finish() }
                        .buttonStyle(.plain)
                        .font(.body.weight(.medium))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .frame(height: 44)
                        .accessibilityIdentifier("onboarding.intro.skip")
                        .transition(.opacity)
                }
            }
            .frame(height: 52)
            .padding(.horizontal, Platform.isMac ? 24 : 16)

            // Pinned from the top so the icon stays put from one card to the next.
            ZStack(alignment: .top) {
                cardView(cards[page])
                    .id(page)
                    .transition(cardTransition)
            }
            .frame(maxWidth: 460)
            .padding(.horizontal, 32)
            .padding(.top, Platform.isMac ? 140 : 110)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .contentShape(Rectangle())
            #if os(iOS)
            .gesture(swipe)
            #endif

            VStack(spacing: 22) {
                dots
                Button {
                    advance()
                } label: {
                    Text(isLast ? "onboarding.intro.start" : "common.continue")
                        .font(.headline)
                        .frame(maxWidth: Platform.isMac ? 240 : .infinity)
                        .frame(height: Platform.isMac ? 36 : 52)
                        .transaction { $0.animation = nil }
                }
                .buttonStyle(.glassProminent)
                .buttonBorderShape(.capsule)
                #if os(macOS)
                .keyboardShortcut(.defaultAction)
                #endif
                .accessibilityIdentifier("onboarding.intro.next")
            }
            .frame(maxWidth: 520)
            .padding(.horizontal, 24)
            .padding(.bottom, Platform.isMac ? 40 : 12)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .animation(reduceMotion ? .easeOut(duration: 0.2) : .spring(duration: 0.45, bounce: 0), value: page)
        #if os(iOS)
        .sensoryFeedback(.selection, trigger: page)
        #endif
    }

    private func cardView(_ card: Card) -> some View {
        VStack(spacing: 18) {
            Color.clear
                .frame(width: 84, height: 84)
                .washBackground(
                    Theme.Wash.accent, flat: Theme.accent,
                    in: RoundedRectangle(cornerRadius: 22, style: .continuous))
                .overlay {
                    Image(systemName: card.symbol)
                        .font(.system(size: 34, weight: .semibold))
                        .foregroundStyle(.white)
                }
                .accessibilityHidden(true)
                .padding(.bottom, 6)
            Text(card.title)
                .font(.system(size: Platform.isMac ? 28 : 30, weight: .bold))
                .accessibilityAddTraits(.isHeader)
            Text(card.body)
                .font(Platform.isMac ? .system(size: 15) : .system(size: 17))
                .foregroundStyle(.secondary)
                .lineSpacing(2)
        }
        .multilineTextAlignment(.center)
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
    }

    private var dots: some View {
        HStack(spacing: 8) {
            ForEach(cards.indices, id: \.self) { index in
                Capsule()
                    .fill(index == page ? Theme.accent : Color.primary.opacity(0.15))
                    .frame(width: index == page ? 18 : 7, height: 7)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("onboarding.progress"))
        .accessibilityValue(Text("onboarding.stepOf \(page + 1) \(cards.count)"))
    }

    private var cardTransition: AnyTransition {
        guard !reduceMotion else { return .opacity }
        return .asymmetric(
            insertion: .offset(x: forward ? 60 : -60).combined(with: .opacity),
            removal: .offset(x: forward ? -60 : 60).combined(with: .opacity))
    }

    private func advance() {
        guard !isLast else { return finish() }
        forward = true
        page += 1
    }

    #if os(iOS)
    private var swipe: some Gesture {
        DragGesture(minimumDistance: 24).onEnded { value in
            if value.translation.width < -40 {
                advance()
            } else if value.translation.width > 40, page > 0 {
                forward = false
                page -= 1
            }
        }
    }
    #endif
}

extension OnboardingIntro {
    private static let seenKey = "OnePassOnboardingIntroSeen"

    /// First launch only. Never under UI tests or the screenshot launch arguments, which drive
    /// the welcome screen directly.
    @MainActor static func shouldShow(for app: AppModel, restoreOnly: Bool) -> Bool {
        let defaults = UserDefaults.standard
        if restoreOnly || app.addingAccount != nil || app.onboardingStart != nil { return false }
        if defaults.bool(forKey: "OnePassTestIsolation") { return false }
        if defaults.string(forKey: "OnePassOnboardingStep") != nil { return false }
        if defaults.bool(forKey: "OnePassSkipIntro") { return false }
        if defaults.bool(forKey: "OnePassShowIntro") { return true }
        return !defaults.bool(forKey: seenKey)
    }

    static func markSeen() {
        UserDefaults.standard.set(true, forKey: seenKey)
    }
}
