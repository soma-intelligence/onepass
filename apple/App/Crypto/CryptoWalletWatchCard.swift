import DesignKit
import SwiftUI
import VaultKit

/// In a crypto wallet's detail: what the watch knows of it (addresses, the xpub, entries that fail
/// their check, the balance when the watch is on), the link to the Crypto screen, and "Dériver les
/// adresses publiques de cette phrase". The derivation runs only on that tap, after a confirmation:
/// the core reads the phrase in memory, returns public data only and wipes it.
struct CryptoWalletWatchCard: View {
    @Environment(AppModel.self) private var model
    let item: FfiItem
    var saved: (FfiItem) -> Void
    @State private var confirmDerive = false
    @State private var deriving = false
    @State private var error: String?

    private var watch: CryptoWatch { model.cryptoWatch }

    var body: some View {
        let info = watch.wallets.first { $0.itemId == item.id }
        let addresses = info?.addresses.count ?? 0
        let hasXpub = info?.xpub != nil
        VStack(alignment: .leading, spacing: 6) {
            Text("crypto.item.header")
                .font(.caption.weight(.bold))
                .tracking(0.6)
                .foregroundStyle(.secondary)
                .padding(.leading, 16)
                .accessibilityAddTraits(.isHeader)
            EditorCard {
                VStack(alignment: .leading, spacing: 10) {
                    if addresses > 0 || hasXpub {
                        HStack {
                            Label {
                                Text("crypto.item.watched \(addresses)")
                            } icon: {
                                Image(systemName: "eye")
                            }
                            if hasXpub { Text(verbatim: "· xpub").foregroundStyle(.secondary) }
                            Spacer()
                            if let value = walletValue {
                                Text(verbatim: value).font(.body.weight(.semibold)).monospacedDigit()
                            }
                        }
                        #if os(iOS)
                        NavigationLink(value: PhoneRoute.crypto) {
                            Label("crypto.item.open", systemImage: "chart.line.uptrend.xyaxis")
                        }
                        .accessibilityIdentifier("item.crypto.open")
                        #endif
                    } else {
                        Text("crypto.item.none")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    if let bad = info?.invalidEntries, !bad.isEmpty {
                        Label {
                            Text("crypto.item.invalid \(bad.count)")
                        } icon: {
                            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        }
                        .font(.subheadline)
                    }
                    if info?.xpubInvalid == true {
                        Label {
                            Text("crypto.item.xpubInvalid")
                        } icon: {
                            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        }
                        .font(.subheadline)
                    }
                    if info?.canDeriveMore == true {
                        Button {
                            confirmDerive = true
                        } label: {
                            Label("crypto.item.derive", systemImage: "key.viewfinder")
                        }
                        .disabled(deriving || item.trashedAt != nil)
                        .accessibilityIdentifier("item.crypto.derive")
                    }
                    if let error {
                        Text(verbatim: error).font(.footnote).foregroundStyle(.red)
                    }
                }
                .editorRowPadding()
            }
        }
        .task(id: item.id) {
            if watch.wallets.isEmpty { await model.prepareCryptoWatch() }
        }
        .confirmationDialog("crypto.item.derive.confirm", isPresented: $confirmDerive, titleVisibility: .visible) {
            Button("crypto.item.derive.action") { Task { await derive() } }
            Button("common.cancel", role: .cancel) {}
        } message: {
            Text("crypto.item.derive.body")
        }
    }

    private var walletValue: String? {
        guard watch.isEnabled, let p = watch.portfolio(),
              let w = p.wallets.first(where: { $0.itemID == item.id }), !w.holdings.isEmpty
        else { return nil }
        return CryptoFormat.money(w.value, currency: p.currency)
    }

    private func derive() async {
        deriving = true
        defer { deriving = false }
        do {
            let updated = try await model.session.addDerivedWatchData(to: item)
            saved(updated)
            await model.prepareCryptoWatch()
            model.showToast(String(localized: "crypto.item.derive.done"))
        } catch {
            self.error = String(localized: "crypto.item.derive.failed")
        }
    }
}

extension FfiWalletWatch {
    /// A phrase is stored and a derivation would add something (no xpub yet, or no Ethereum or
    /// Solana address).
    var canDeriveMore: Bool {
        hasPhrase && (xpub == nil || !addresses.contains { $0.chain == .ethereum } || !addresses.contains { $0.chain == .solana })
    }
}
