import DesignKit
import SwiftUI
import VaultKit

/// Card at the top of a login whose site offers two-factor authentication or a passkey it does
/// not use yet: collapsible, with the main button (`SiteSetupButton`) and "Ignorer" (the check is
/// excluded for this item, saved). Passkey in purple, two-factor in the Watchtower 2FA blue.
struct SiteSetupBanner: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let offer: SiteSetupOffer
    let onIgnore: () -> Void
    @State private var expanded = true

    var body: some View {
        let style = SiteSetupStyle(offer.kind)
        VStack(alignment: .leading, spacing: Theme.Space.m) {
            Button {
                withAnimation(FoldMotion.animation(reduceMotion: reduceMotion)) { expanded.toggle() }
            } label: {
                HStack(spacing: Theme.Space.s) {
                    Image(systemName: style.symbol)
                    Text(style.title).font(.headline)
                    Spacer()
                    Image(systemName: "chevron.down")
                        .font(.caption.weight(.bold))
                        .rotationEffect(.degrees(expanded ? 0 : -90))
                }
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("\(style.identifier).toggle")
            if expanded {
                Text(message)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: Theme.Space.m) {
                    SiteSetupButton(offer: offer)
                    Button("Ignorer", action: onIgnore)
                        .buttonStyle(.bordered)
                        .accessibilityIdentifier("\(style.identifier).ignore")
                }
            }
        }
        .padding(Theme.Space.l)
        .background(style.tint.opacity(0.16), in: .rect(cornerRadius: Theme.Radius.card, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous).stroke(style.tint.opacity(0.35)))
        .accessibilityIdentifier(style.identifier)
    }

    private var message: LocalizedStringKey {
        switch offer.kind {
        case .twoFactor: "item.siteOffersTwoFactor"
        case .passkey: "item.supportsPasskeysPasskeyReplaces \(offer.host)"
        }
    }
}

/// The main button of a site setup offer: opens the site's settings, its help page (2FA), or its
/// passkey enrollment page, looked up only when tapped (`PasskeyEnrollment.page`).
struct SiteSetupButton: View {
    @Environment(\.openURL) private var openURL
    let offer: SiteSetupOffer
    @State private var finding = false

    var body: some View {
        let style = SiteSetupStyle(offer.kind)
        Button(label) { open() }
            .buttonStyle(.borderedProminent)
            .tint(style.tint)
            .disabled(finding)
            .accessibilityIdentifier("\(style.identifier).\(offer.kind == .passkey ? "use" : "open")")
    }

    private var label: LocalizedStringKey {
        switch (offer.kind, offer.action) {
        case (.passkey, _): "item.usePasskey"
        case (.twoFactor, .seeHow): "item.seeHow"
        case (.twoFactor, _): "item.openSettings"
        }
    }

    private func open() {
        switch offer.action {
        case .openSettings(let url), .seeHow(let url):
            openURL(url)
        case .findPasskeyPage(let host):
            finding = true
            Task {
                let url = await PasskeyEnrollment.page(for: host)
                finding = false
                openURL(url)
            }
        }
    }
}

/// Tint, symbol, title and accessibility identifier prefix of each kind of offer.
private struct SiteSetupStyle {
    let tint: Color
    let symbol: String
    let title: LocalizedStringKey
    let identifier: String

    init(_ kind: SiteSetupOffer.Kind) {
        switch kind {
        case .passkey:
            tint = Color(red: 0.55, green: 0.36, blue: 0.96)
            symbol = "person.badge.key.fill"
            title = "item.passkeyAvailable"
            identifier = "item.passkeyOffer"
        case .twoFactor:
            tint = Color(red: 0.04, green: 0.39, blue: 0.78)
            symbol = "lock.shield.fill"
            title = "item.twoFactorAvailable"
            identifier = "item.twoFactorOffer"
        }
    }
}
