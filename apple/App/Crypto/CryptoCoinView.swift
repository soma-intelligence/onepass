import Charts
import DesignKit
import SwiftUI
import VaultKit

/// One coin: value held and its chart over the period, the amount per wallet and address, each
/// address with Copier and its QR code, and "Ouvrir dans…" (hand-off to the wallet app).
struct CryptoCoinView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.colorScheme) private var colorScheme
    let coin: String
    @State private var selection: Date?
    @State private var receive: ReceiveAddress?

    private var watch: CryptoWatch { model.cryptoWatch }

    var body: some View {
        let portfolio = watch.portfolio()
        let holding = portfolio?.holdings.first { $0.coin == coin }
        let asset = CryptoCatalog.coin(coin)
        let currency = portfolio?.currency ?? watch.settings.currency
        let price = watch.snapshot?.prices[coin]
        let points = watch.snapshot?.charts[coin]?[watch.settings.period] ?? []
        ScrollView {
            VStack(spacing: 18) {
                VStack(spacing: 6) {
                    CoinIcon(coin: coin, symbol: asset?.symbol ?? "", size: 56)
                    if let holding {
                        Text(verbatim: holding.value.map { CryptoFormat.money($0, currency: currency) }
                             ?? CryptoFormat.amount(holding.amount, symbol: holding.symbol))
                            .font(.system(size: 40, weight: .bold, design: .rounded))
                            .monospacedDigit()
                            .minimumScaleFactor(0.5)
                            .lineLimit(1)
                            .accessibilityIdentifier("crypto.coin.value")
                        Text(verbatim: CryptoFormat.amount(holding.amount, symbol: holding.symbol))
                            .font(.subheadline.weight(.medium))
                            .foregroundStyle(.secondary)
                    }
                    if let price {
                        HStack(spacing: 8) {
                            Text("crypto.coin.price \(CryptoFormat.money(price.price, currency: currency))")
                                .foregroundStyle(.secondary)
                            ChangeLabel(change: change(points: points, price: price))
                        }
                        .font(.subheadline)
                    }
                }
                .padding(.top, 20)
                if points.count > 1 {
                    let selected = selection.flatMap { s in points.min { abs($0.date.timeIntervalSince(s)) < abs($1.date.timeIntervalSince(s)) } }
                    Text(verbatim: selected.map {
                        "\(CryptoFormat.money(Decimal($0.value), currency: currency)) · \($0.date.formatted(date: .abbreviated, time: .shortened))"
                    } ?? " ")
                    .font(.footnote.monospacedDigit())
                    .foregroundStyle(.secondary)
                    CryptoLineChart(points: points, color: colorScheme == .dark ? .white : Color(red: 0.20, green: 0.18, blue: 0.55),
                                    baseline: true, selection: $selection)
                        .frame(height: 200)
                }
                PeriodPicker(period: Binding(get: { watch.settings.period }, set: { p in watch.update { $0.period = p } }))
                    .padding(.horizontal, 24)
                if let holding {
                    CryptoCard {
                        CryptoCardTitle(title: "crypto.coin.byWallet")
                        ForEach(Array(holding.parts.enumerated()), id: \.offset) { _, part in
                            partRow(part, symbol: holding.symbol, price: holding.price, currency: currency)
                        }
                        .padding(.bottom, 6)
                    }
                    .padding(.horizontal, 16)
                }
                if let chain = asset?.chain {
                    WalletHandoffMenu(address: ReceiveAddress.all(watch, chain: chain).first) {
                        Label("crypto.action.openIn", systemImage: "arrow.up.forward.app")
                            .font(.body.weight(.semibold))
                            .padding(.horizontal, 10)
                            .frame(minHeight: 40)
                    }
                    .buttonStyle(.glass)
                    .accessibilityIdentifier("crypto.coin.openIn")
                }
                Text("crypto.readOnly.notice")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 28)
            }
            .padding(.bottom, 32)
            .frame(maxWidth: 640)
            .frame(maxWidth: .infinity)
        }
        .background { CryptoBackdrop() }
        .navigationTitle(Text(verbatim: holding?.name ?? asset?.name ?? coin))
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .refreshable { await watch.refresh() }
        .onChange(of: watch.settings.period) { Task { await watch.refreshIfStale() } }
        .sheet(item: $receive) { a in
            CryptoReceiveSheet(addresses: [a])
        }
        .environment(watch)
    }

    private func change(points: [CryptoChartPoint], price: CryptoPrice) -> Double? {
        if let f = points.first?.value, let l = points.last?.value, f > 0 { return (l - f) / f * 100 }
        return watch.settings.period == .day ? price.change24h : nil
    }

    private func partRow(_ part: CryptoHolding.Part, symbol: String, price: Decimal?, currency: String) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: part.wallet).font(.body.weight(.medium))
                Text(verbatim: part.fromXpub
                     ? String(localized: "crypto.coin.xpub \(CryptoFormat.short(part.address))")
                     : "\(part.chain.name) · \(CryptoFormat.short(part.address))")
                    .font(.footnote.monospaced())
                    .foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text(verbatim: CryptoFormat.amount(part.amount, symbol: symbol)).font(.subheadline.weight(.medium)).monospacedDigit()
                if let price {
                    Text(verbatim: CryptoFormat.money(part.amount * price, currency: currency))
                        .font(.footnote).foregroundStyle(.secondary).monospacedDigit()
                }
            }
            Menu {
                if !part.fromXpub {
                    Button("common.copy", systemImage: "doc.on.doc") {
                        model.session.copy(part.address, concealed: false)
                        model.showToast(String(localized: "crypto.copied"))
                    }
                    Button("crypto.coin.showQR", systemImage: "qrcode") {
                        receive = ReceiveAddress(chain: part.chain, address: part.address, wallet: part.wallet)
                    }
                } else if let next = watch.snapshot?.wallets.first(where: { $0.itemID == part.itemID })?.nextReceive {
                    Button("crypto.coin.nextReceive", systemImage: "qrcode") {
                        receive = ReceiveAddress(chain: .bitcoin, address: next, wallet: part.wallet)
                    }
                }
                #if os(iOS)
                NavigationLink(value: PhoneRoute.item(ItemRef(vaultID: part.vaultID, itemID: part.itemID))) {
                    Label("crypto.coin.openItem", systemImage: "wallet.bifold")
                }
                #endif
            } label: {
                Image(systemName: "ellipsis")
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .frame(width: 32, height: 44)
                    .contentShape(.rect)
            }
            .accessibilityLabel(Text("crypto.coin.actions"))
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 8)
    }
}
