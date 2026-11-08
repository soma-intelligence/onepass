#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Watchtower (spec 2026-11-02-crypto-watch, section 7): wallets with a non-zero watched balance
/// whose recovery phrase is stored without per-item Travel Mode protection. "Voir les éléments"
/// lists them; each item's detail carries the Travel Mode switches ("Masquer en Travel Mode",
/// "Protection renforcée") where the per-item travel feature is present. The card reads the
/// cached balances only: Watchtower never triggers a balance request.
struct CryptoPhraseAlertCard: View {
    @Environment(AppModel.self) private var model

    private static let fill = Color(red: 0.70, green: 0.30, blue: 0.0)

    var body: some View {
        let wallets = model.cryptoWatch.unprotectedFundedWallets
        Group {
            if !wallets.isEmpty {
                NavigationLink(value: PhoneRoute.watchtower(
                    title: String(localized: "crypto.watchtower.title"), itemIDs: Set(wallets.map(\.itemId)))) {
                    VStack(alignment: .leading, spacing: 0) {
                        VStack(alignment: .leading, spacing: 6) {
                            HStack(alignment: .top) {
                                Text(wallets.count, format: .number)
                                    .font(.system(size: 44, weight: .bold, design: .rounded))
                                    .monospacedDigit()
                                Spacer()
                                Image(systemName: "key.horizontal.fill")
                                    .font(.system(size: 30, weight: .semibold))
                                    .opacity(0.35)
                                    .accessibilityHidden(true)
                            }
                            Text("crypto.watchtower.title").font(.headline)
                            Text("crypto.watchtower.body")
                                .font(.subheadline)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(16)
                        Rectangle().fill(.white.opacity(0.25)).frame(height: 0.5)
                        HStack {
                            Text("crypto.watchtower.action").font(.body.weight(.medium))
                            Spacer()
                            Image(systemName: "chevron.forward").font(.footnote.weight(.bold))
                        }
                        .padding(.horizontal, 16)
                        .frame(minHeight: 48)
                    }
                    .foregroundStyle(.white)
                    .multilineTextAlignment(.leading)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .washBackground(
                        Theme.Wash.alert(Self.fill), flat: Self.fill,
                        in: RoundedRectangle(cornerRadius: PhoneCard.radius, style: .continuous))
                    .contentShape(.rect(cornerRadius: PhoneCard.radius))
                }
                .buttonStyle(PressableButtonStyle())
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("watchtower.show.cryptoPhrase")
            }
        }
        .task { await model.prepareCryptoWatch() }
    }
}
#endif
