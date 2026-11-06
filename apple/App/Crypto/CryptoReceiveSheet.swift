import DesignKit
import SwiftUI
import VaultKit

/// A public address the user can receive on.
struct ReceiveAddress: Hashable, Identifiable {
    var id: String { "\(chain.rawValue):\(address)" }
    var chain: CryptoChain
    var address: String
    var wallet: String

    /// The payment URI of the chain (BIP21, EIP-681, Solana Pay): wallets read it from the QR.
    var uri: String {
        switch chain {
        case .bitcoin: "bitcoin:\(address)"
        case .ethereum: "ethereum:\(address)"
        case .solana: "solana:\(address)"
        }
    }

    /// Every address the watch knows, with each xpub's next unused receive address.
    @MainActor
    static func all(_ watch: CryptoWatch, chain: CryptoChain? = nil) -> [ReceiveAddress] {
        var out: [ReceiveAddress] = []
        for w in watch.wallets {
            if w.xpub != nil, chain == nil || chain == .bitcoin,
               let next = watch.snapshot?.wallets.first(where: { $0.itemID == w.itemId })?.nextReceive {
                out.append(ReceiveAddress(chain: .bitcoin, address: next, wallet: w.title))
            }
            for a in w.addresses where chain == nil || CryptoChain(a.chain) == chain {
                out.append(ReceiveAddress(chain: CryptoChain(a.chain), address: a.address, wallet: w.title))
            }
        }
        var seen = Set<String>()
        return out.filter { seen.insert($0.id).inserted }
    }
}

/// "Recevoir": one address at a time, as a QR code and as text, with Copier and Partager. Public data:
/// nothing to mask. Nothing is signed or sent from here.
struct CryptoReceiveSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppModel.self) private var model
    let addresses: [ReceiveAddress]
    @State private var selected: ReceiveAddress?
    @State private var copied = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 18) {
                    if addresses.count > 1 {
                        Picker(selection: $selected) {
                            ForEach(addresses) { a in
                                Text(verbatim: "\(a.chain.name) · \(a.wallet)").tag(Optional(a))
                            }
                        } label: {
                            Text("crypto.receive.address")
                        }
                        .pickerStyle(.menu)
                        .accessibilityIdentifier("crypto.receive.picker")
                    }
                    if let a = selected ?? addresses.first {
                        ZStack {
                            RoundedRectangle(cornerRadius: 24, style: .continuous).fill(.white)
                            if let image = WifiQR.image(for: a.uri) {
                                Image(decorative: image, scale: 1)
                                    .interpolation(.none)
                                    .resizable()
                                    .scaledToFit()
                                    .padding(18)
                            }
                            CoinIcon(coin: a.chain.native.coin, symbol: a.chain.native.symbol, size: 44)
                                .padding(4)
                                .background(.white, in: .circle)
                        }
                        .frame(width: 260, height: 260)
                        .environment(\.colorScheme, .light)
                        .accessibilityLabel(Text("crypto.receive.qr \(a.chain.name)"))
                        Text(verbatim: a.address)
                            .font(.body.monospaced())
                            .multilineTextAlignment(.center)
                            .textSelection(.enabled)
                            .padding(.horizontal, 24)
                        Text("crypto.receive.only \(a.chain.name)")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 24)
                        HStack(spacing: 12) {
                            Button {
                                model.session.copy(a.address, concealed: false)
                                copied = true
                            } label: {
                                Label(copied ? "common.copied" : "common.copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                                    .frame(minWidth: 110, minHeight: 36)
                            }
                            .buttonStyle(.glass)
                            .accessibilityIdentifier("crypto.receive.copy")
                            ShareLink(item: a.address) {
                                Label("common.share", systemImage: "square.and.arrow.up")
                                    .frame(minWidth: 110, minHeight: 36)
                            }
                            .buttonStyle(.glass)
                        }
                    } else {
                        ContentUnavailableView {
                            Label("crypto.receive.none", systemImage: "qrcode")
                        } description: {
                            Text("crypto.receive.none.body")
                        }
                    }
                }
                .padding(.vertical, 24)
                .frame(maxWidth: .infinity)
            }
            .navigationTitle(Text("crypto.action.receive"))
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("common.done") { dismiss() }
                }
            }
            .onChange(of: selected) { copied = false }
        }
    }
}

/// "Ouvrir dans…": hands off to the user's wallet app. OnePass only opens the app (its URL scheme,
/// or the chain's payment URI for the system's default wallet); the user swaps or sends there.
struct WalletHandoffMenu<Label: View>: View {
    @Environment(\.openURL) private var openURL
    @Environment(CryptoWatch.self) private var watch
    var address: ReceiveAddress?
    @ViewBuilder var label: Label
    @State private var failed = false

    /// Common wallets and their URL schemes.
    static var wallets: [(name: String, scheme: String)] {
        [
            ("Ledger Live", "ledgerlive://"),
            ("MetaMask", "metamask://"),
            ("Phantom", "phantom://"),
            ("Coinbase Wallet", "cbwallet://"),
            ("Trust Wallet", "trust://"),
            ("Exodus", "exodus://"),
            ("Rainbow", "rainbow://"),
            ("Solflare", "solflare://"),
            ("BlueWallet", "bluewallet://"),
        ]
    }

    var body: some View {
        Menu {
            if let custom = watch.settings.handoffScheme, let url = URL(string: custom) {
                Button {
                    open(url)
                } label: {
                    SwiftUI.Label(watch.settings.handoffName ?? custom, systemImage: "star")
                }
            }
            if let address {
                Button {
                    if let url = URL(string: address.uri) { open(url) }
                } label: {
                    SwiftUI.Label("crypto.handoff.default \(address.chain.name)", systemImage: "app.badge")
                }
            }
            Section {
                ForEach(Self.wallets, id: \.scheme) { w in
                    Button(w.name) {
                        if let url = URL(string: w.scheme) { open(url) }
                    }
                }
            } header: {
                Text("crypto.handoff.header")
            }
        } label: {
            label
        }
        .alert("crypto.handoff.failed", isPresented: $failed) {
            Button("common.ok", role: .cancel) {}
        } message: {
            Text("crypto.handoff.failed.body")
        }
    }

    private func open(_ url: URL) {
        openURL(url) { accepted in
            if !accepted { failed = true }
        }
    }
}
