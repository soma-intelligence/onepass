import Charts
import DesignKit
import SwiftUI
import VaultKit

/// "Crypto" (spec 2026-11-02-crypto-watch, section 6): watch-only balances of the crypto wallet
/// items. The total in the user's currency with its change over the period and a full-width line
/// chart on an indigo wash, four round actions (Recevoir, Ouvrir dans…, Actualiser, Plus), then the
/// cards the user orders: holdings per wallet, Bitcoin and Ether tiles, movers among the holdings,
/// the market. Read only: nothing here signs, sends or swaps; "Ouvrir dans…" opens the user's
/// wallet app. Balances are fetched when the screen opens and on pull to refresh, never otherwise.
struct CryptoPortfolioView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.colorScheme) private var colorScheme
    @State private var selection: Date?
    @State private var showReceive = false
    @State private var showSettings = false
    @State private var showCustomize = false
    @State private var collapsed: Set<String> = []
    @State private var moversUp = true
    @State private var marketExpanded = false

    private var watch: CryptoWatch { model.cryptoWatch }

    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                if !watch.isEnabled {
                    CryptoOffCard { showSettings = true }
                        .padding(.top, 40)
                } else if watch.targets.isEmpty {
                    CryptoEmptyCard()
                        .padding(.top, 40)
                } else if let portfolio = watch.portfolio() {
                    header(portfolio)
                    actions
                    ForEach(watch.settings.visibleSections, id: \.self) { section in
                        sectionView(section, portfolio)
                    }
                    customizeButton
                    footer
                } else {
                    ProgressView().padding(.top, 120)
                }
            }
            .padding(.bottom, 32)
            .frame(maxWidth: 640)
            .frame(maxWidth: .infinity)
        }
        .background { CryptoBackdrop() }
        .navigationTitle(Text("crypto.title"))
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("crypto.settings.title", systemImage: "gearshape") { showSettings = true }
                    .accessibilityIdentifier("crypto.settings")
            }
        }
        .refreshable { await watch.refresh() }
        .task {
            await model.prepareCryptoWatch()
            await watch.refreshIfStale()
        }
        .onChange(of: watch.settings.period) {
            Task { await watch.refreshIfStale() }
        }
        .sheet(isPresented: $showReceive) {
            CryptoReceiveSheet(addresses: ReceiveAddress.all(watch))
        }
        .sheet(isPresented: $showSettings) {
            NavigationStack { CryptoSettingsView(showsDone: true) }
        }
        .sheet(isPresented: $showCustomize) {
            CryptoCustomizeSheet()
        }
        .environment(watch)
        .accessibilityIdentifier("page.crypto")
    }

    // MARK: Header

    private func header(_ p: CryptoPortfolio) -> some View {
        let point = selection.flatMap { s in p.history.min { abs($0.date.timeIntervalSince(s)) < abs($1.date.timeIntervalSince(s)) } }
        let shown = point.map { Decimal($0.value) } ?? p.total
        let (whole, rest) = CryptoFormat.split(CryptoFormat.money(shown, currency: p.currency))
        return VStack(spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 0) {
                Text(verbatim: whole)
                    .font(.system(size: 54, weight: .bold, design: .rounded))
                Text(verbatim: rest)
                    .font(.system(size: 26, weight: .bold, design: .rounded))
            }
            .monospacedDigit()
            .minimumScaleFactor(0.5)
            .lineLimit(1)
            .contentTransition(.numericText())
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("crypto.total \(CryptoFormat.money(shown, currency: p.currency))"))
            .accessibilityIdentifier("crypto.total")
            HStack(spacing: 10) {
                if let point, let first = p.history.first {
                    Text(verbatim: point.date.formatted(date: .abbreviated, time: .shortened))
                        .foregroundStyle(.secondary)
                    ChangeLabel(change: first.value > 0 ? (point.value - first.value) / first.value * 100 : nil)
                } else {
                    if let v = p.changeValue {
                        Text(verbatim: (v >= 0 ? "+" : "") + CryptoFormat.money(v, currency: p.currency))
                            .monospacedDigit()
                            .foregroundStyle(.secondary)
                    }
                    ChangeLabel(change: p.changePercent)
                }
            }
            .font(.subheadline.weight(.medium))
            .frame(minHeight: 20)
            if p.history.count > 1 {
                CryptoLineChart(points: p.history, color: chartColor, lineWidth: 2.5, selection: $selection)
                    .frame(height: 210)
                    .padding(.top, 18)
            } else {
                Color.clear.frame(height: 60)
            }
            PeriodPicker(period: Binding(
                get: { watch.settings.period },
                set: { p in watch.update { $0.period = p } }))
                .padding(.horizontal, 24)
                .padding(.top, 6)
        }
        .padding(.top, 28)
    }

    /// White over the deep indigo of dark mode, the accent's dark shade over the light wash.
    private var chartColor: Color {
        colorScheme == .dark ? .white : Color(red: 0.20, green: 0.18, blue: 0.55)
    }

    // MARK: Actions

    private var actions: some View {
        HStack(alignment: .top, spacing: 0) {
            CryptoActionButton(title: "crypto.action.receive", systemImage: "arrow.down") { showReceive = true }
                .accessibilityIdentifier("crypto.receive")
            WalletHandoffMenu(address: ReceiveAddress.all(watch).first) {
                CryptoActionLabel(title: "crypto.action.openIn", systemImage: "arrow.up.forward.app")
            }
            .frame(maxWidth: .infinity)
            .accessibilityIdentifier("crypto.openIn")
            CryptoActionButton(title: "crypto.action.refresh", systemImage: "arrow.clockwise") {
                Task { await watch.refresh() }
            }
            .disabled(watch.phase == .refreshing)
            .accessibilityIdentifier("crypto.refresh")
            Menu {
                Button("crypto.settings.title", systemImage: "gearshape") { showSettings = true }
                Button("crypto.customize", systemImage: "rectangle.3.group") { showCustomize = true }
            } label: {
                CryptoActionLabel(title: "crypto.action.more", systemImage: "ellipsis")
            }
            .frame(maxWidth: .infinity)
            .accessibilityIdentifier("crypto.more")
        }
        .padding(.horizontal, 12)
        .padding(.top, 8)
    }

    // MARK: Sections

    @ViewBuilder private func sectionView(_ section: CryptoSection, _ p: CryptoPortfolio) -> some View {
        switch section {
        case .holdings:
            ForEach(p.wallets) { wallet in
                walletCard(wallet, currency: p.currency)
            }
        case .tiles:
            tiles(p)
        case .movers:
            if p.holdings.count > 1 { movers(p) }
        case .market:
            if let market = watch.snapshot?.market, !market.isEmpty { marketCard(market, currency: p.currency) }
        }
    }

    private func walletCard(_ w: CryptoWalletTotal, currency: String) -> some View {
        let open = !collapsed.contains(w.itemID)
        return CryptoCard {
            Button {
                withAnimation(.snappy) {
                    if open { collapsed.insert(w.itemID) } else { collapsed.remove(w.itemID) }
                }
            } label: {
                HStack(spacing: 14) {
                    Image(systemName: "wallet.bifold")
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(Theme.readableAccent)
                        .frame(width: 42, height: 42)
                        .background(Theme.accent.opacity(0.14), in: .circle)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: w.title).font(.body.weight(.semibold)).foregroundStyle(.primary)
                        HStack(spacing: 6) {
                            Text(verbatim: CryptoFormat.money(w.value, currency: currency))
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                            ChangeLabel(change: w.change)
                        }
                        .font(.subheadline)
                    }
                    Spacer()
                    Image(systemName: "chevron.up")
                        .font(.footnote.weight(.bold))
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(open ? 0 : 180))
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 14)
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityValue(open ? Text("crypto.expanded") : Text("crypto.collapsed"))
            if open {
                if w.holdings.isEmpty {
                    Text("crypto.wallet.empty")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 18)
                        .padding(.bottom, 16)
                } else {
                    VStack(spacing: 0) {
                        ForEach(w.holdings) { h in
                            coinLink(h.coin) { HoldingRow(holding: h, currency: currency) }
                        }
                    }
                    .padding(.vertical, 6)
                    .background(Color.primary.opacity(colorScheme == .dark ? 0.04 : 0.025),
                                in: .rect(cornerRadius: 22, style: .continuous))
                    .padding([.horizontal, .bottom], 6)
                }
            }
        }
        .padding(.horizontal, 16)
    }

    @ViewBuilder private func coinLink<L: View>(_ coin: String, @ViewBuilder label: () -> L) -> some View {
        #if os(iOS)
        NavigationLink(value: PhoneRoute.cryptoCoin(coin)) { label() }
            .buttonStyle(.plain)
            .accessibilityIdentifier("crypto.coin.\(coin)")
        #else
        NavigationLink(value: CryptoCoinRoute(coin: coin)) { label() }
            .buttonStyle(.plain)
        #endif
    }

    private func tiles(_ p: CryptoPortfolio) -> some View {
        let held = p.holdings.filter { watch.snapshot?.charts[$0.coin]?[watch.settings.period] != nil }.map(\.coin)
        let coins = Array((held + ["bitcoin", "ethereum"]).reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }.prefix(2))
        return HStack(spacing: 12) {
            ForEach(coins, id: \.self) { coin in
                coinLink(coin) { PriceTile(coin: coin, currency: p.currency) }
            }
        }
        .padding(.horizontal, 16)
    }

    private func movers(_ p: CryptoPortfolio) -> some View {
        let ranked = p.holdings.filter { $0.change != nil }
            .sorted { moversUp ? $0.change! > $1.change! : $0.change! < $1.change! }
            .filter { moversUp ? $0.change! >= 0 : $0.change! < 0 }
            .prefix(4)
        return CryptoCard {
            CryptoCardTitle(title: "crypto.movers")
            Picker(selection: $moversUp) {
                Text("crypto.movers.up").tag(true)
                Text("crypto.movers.down").tag(false)
            } label: {
                Text("crypto.movers")
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 18)
            .padding(.vertical, 8)
            if ranked.isEmpty {
                Text(moversUp ? "crypto.movers.noneUp" : "crypto.movers.noneDown")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 18)
            } else {
                HStack(alignment: .top, spacing: 0) {
                    ForEach(Array(ranked)) { h in
                        coinLink(h.coin) {
                            VStack(spacing: 6) {
                                CoinIcon(coin: h.coin, symbol: h.symbol, size: 52)
                                Text(verbatim: h.symbol).font(.footnote.weight(.semibold))
                                ChangeLabel(change: h.change, font: .footnote)
                            }
                            .frame(maxWidth: .infinity)
                        }
                    }
                }
                .padding(.vertical, 14)
            }
        }
        .padding(.horizontal, 16)
    }

    private func marketCard(_ market: [CryptoMarketCoin], currency: String) -> some View {
        let shown = marketExpanded ? market : Array(market.prefix(5))
        return CryptoCard {
            CryptoCardTitle(title: "crypto.market")
            ForEach(shown) { c in
                HStack(spacing: 14) {
                    CoinIcon(coin: c.id, symbol: c.symbol, size: 42)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: c.name).font(.body.weight(.medium)).lineLimit(1)
                        Text(verbatim: c.symbol).font(.subheadline).foregroundStyle(.secondary)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(verbatim: CryptoFormat.money(c.price, currency: currency))
                            .font(.body.weight(.medium))
                            .monospacedDigit()
                        ChangeLabel(change: c.change24h)
                    }
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 10)
                .accessibilityElement(children: .combine)
            }
            if market.count > 5 {
                Button(marketExpanded ? "crypto.market.less" : "crypto.market.all") {
                    withAnimation(.snappy) { marketExpanded.toggle() }
                }
                .font(.body.weight(.semibold))
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
            }
            Text("crypto.market.note")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .padding(.horizontal, 18)
                .padding(.bottom, 14)
        }
        .padding(.horizontal, 16)
    }

    private var customizeButton: some View {
        Button { showCustomize = true } label: {
            Label("crypto.customize", systemImage: "plus")
                .font(.body.weight(.semibold))
                .padding(.horizontal, 10)
                .frame(minHeight: 40)
        }
        .buttonStyle(.glass)
        .padding(.top, 6)
        .accessibilityIdentifier("crypto.customize")
    }

    private var footer: some View {
        VStack(spacing: 8) {
            if let snap = watch.snapshot {
                if watch.phase == .offline {
                    Label {
                        Text("crypto.asOf.offline \(snap.fetchedAt.formatted(date: .abbreviated, time: .shortened))")
                    } icon: {
                        Image(systemName: "wifi.slash")
                    }
                    .foregroundStyle(.orange)
                } else if watch.phase == .refreshing {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("crypto.refreshing")
                    }
                } else {
                    Text("crypto.asOf \(snap.fetchedAt.formatted(date: .omitted, time: .shortened))")
                }
                if snap.wallets.contains(where: { !$0.failed.isEmpty }), watch.phase != .offline {
                    Text("crypto.partial").foregroundStyle(.orange)
                }
            }
            Text("crypto.privacy.notice")
            Text("crypto.readOnly.notice")
        }
        .font(.footnote)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
        .padding(.horizontal, 28)
        .padding(.top, 4)
    }
}

/// The indigo wash behind the header: deep in dark mode, pale in light mode, fading into the page.
struct CryptoBackdrop: View {
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        let top = scheme == .dark ? Color(red: 0.20, green: 0.17, blue: 0.48) : Theme.accent.opacity(0.30)
        let mid = scheme == .dark ? Color(red: 0.11, green: 0.09, blue: 0.24) : Theme.accent.opacity(0.10)
        // The wash fades into the page color, which fills the whole screen below it.
        ZStack(alignment: .top) {
            PageBackground()
            LinearGradient(stops: [
                .init(color: top, location: 0),
                .init(color: mid, location: 0.55),
                .init(color: .clear, location: 1),
            ], startPoint: .top, endPoint: .bottom)
            .frame(height: 720)
            .frame(maxWidth: .infinity)
        }
        .ignoresSafeArea()
    }
}

/// The grouped page color under the wash.
private struct PageBackground: View {
    var body: some View {
        #if os(macOS)
        Color(nsColor: .windowBackgroundColor).ignoresSafeArea()
        #else
        Color(uiColor: .systemGroupedBackground).ignoresSafeArea()
        #endif
    }
}

/// A round glass action with its label under it.
struct CryptoActionButton: View {
    let title: LocalizedStringKey
    let systemImage: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            CryptoActionLabel(title: title, systemImage: systemImage)
        }
        .buttonStyle(.plain)
        .frame(maxWidth: .infinity)
    }
}

struct CryptoActionLabel: View {
    @Environment(\.isEnabled) private var enabled
    let title: LocalizedStringKey
    let systemImage: String

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: systemImage)
                .font(.system(size: 19, weight: .semibold))
                .foregroundStyle(.primary)
                .frame(width: 56, height: 56)
                .glassEffect(.regular.interactive(), in: .circle)
            Text(title)
                .font(.footnote.weight(.medium))
                .foregroundStyle(.primary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
        .opacity(enabled ? 1 : 0.5)
        .contentShape(.rect)
    }
}

/// A coin's price tile: ticker, mark, price, change, sparkline over the period with a dotted line at
/// the open and a soft fill.
struct PriceTile: View {
    @Environment(CryptoWatch.self) private var watch
    let coin: String
    let currency: String

    var body: some View {
        let asset = CryptoCatalog.coin(coin)
        let price = watch.snapshot?.prices[coin]
        let points = watch.snapshot?.charts[coin]?[watch.settings.period] ?? []
        let change: Double? = {
            if let f = points.first?.value, let l = points.last?.value, f > 0 { return (l - f) / f * 100 }
            return watch.settings.period == .day ? price?.change24h : nil
        }()
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(verbatim: asset?.symbol ?? coin.uppercased())
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                CoinIcon(coin: coin, symbol: asset?.symbol ?? "", size: 26)
            }
            if let price {
                Text(verbatim: CryptoFormat.money(price.price, currency: currency))
                    .font(.title3.weight(.bold))
                    .monospacedDigit()
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
            }
            ChangeLabel(change: change, font: .footnote)
            if points.count > 1 {
                CryptoLineChart(points: points, color: CryptoFormat.color(change), lineWidth: 1.6,
                                baseline: true, fill: true)
                    .frame(height: 70)
                    .padding(.top, 6)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.regularMaterial, in: .rect(cornerRadius: 26, style: .continuous))
        .overlay { RoundedRectangle(cornerRadius: 26, style: .continuous).strokeBorder(Color.primary.opacity(0.06)) }
        .accessibilityElement(children: .combine)
    }
}

/// The watch is off: what it does, what leaves the device, and the switch.
struct CryptoOffCard: View {
    let turnOn: () -> Void

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "chart.line.uptrend.xyaxis")
                .font(.system(size: 34, weight: .semibold))
                .foregroundStyle(Theme.readableAccent)
                .frame(width: 72, height: 72)
                .background(Theme.accent.opacity(0.14), in: .circle)
            Text("crypto.off.title").font(.title2.weight(.bold)).multilineTextAlignment(.center)
            Text("crypto.off.body")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button(action: turnOn) {
                Text("crypto.off.action").font(.headline).padding(.horizontal, 8).frame(minHeight: 34)
            }
            .buttonStyle(.glassProminent)
            .accessibilityIdentifier("crypto.turnOn")
        }
        .padding(.horizontal, 32)
    }
}

/// On, but no wallet has a public address or an xpub yet.
struct CryptoEmptyCard: View {
    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "wallet.bifold")
                .font(.system(size: 32, weight: .semibold))
                .foregroundStyle(Theme.readableAccent)
                .frame(width: 72, height: 72)
                .background(Theme.accent.opacity(0.14), in: .circle)
            Text("crypto.empty.title").font(.title2.weight(.bold)).multilineTextAlignment(.center)
            Text("crypto.empty.body")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            #if os(iOS)
            NavigationLink(value: PhoneRoute.list(.category(.cryptoWallet))) {
                Text("crypto.empty.action").font(.headline).padding(.horizontal, 8).frame(minHeight: 34)
            }
            .buttonStyle(.glassProminent)
            #endif
        }
        .padding(.horizontal, 32)
    }
}

/// "Personnaliser": order and show the cards.
struct CryptoCustomizeSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(CryptoWatch.self) private var watch

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(watch.settings.sections, id: \.self) { s in
                        Toggle(isOn: Binding(
                            get: { !watch.settings.hiddenSections.contains(s) },
                            set: { on in watch.update { if on { $0.hiddenSections.remove(s) } else { $0.hiddenSections.insert(s) } } }
                        )) {
                            Label(Self.title(s), systemImage: Self.symbol(s))
                        }
                    }
                    .onMove { from, to in watch.update { $0.sections.move(fromOffsets: from, toOffset: to) } }
                } footer: {
                    Text("crypto.customize.footer")
                }
            }
            #if os(iOS)
            .environment(\.editMode, .constant(.active))
            #endif
            .navigationTitle(Text("crypto.customize"))
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("common.done") { dismiss() }
                }
            }
        }
    }

    static func title(_ s: CryptoSection) -> LocalizedStringKey {
        switch s {
        case .holdings: "crypto.section.holdings"
        case .tiles: "crypto.section.tiles"
        case .movers: "crypto.movers"
        case .market: "crypto.market"
        }
    }

    static func symbol(_ s: CryptoSection) -> String {
        switch s {
        case .holdings: "wallet.bifold"
        case .tiles: "square.grid.2x2"
        case .movers: "arrow.up.arrow.down"
        case .market: "chart.bar"
        }
    }
}

/// A coin of the Crypto screen on the Mac (the phone uses `PhoneRoute.cryptoCoin`).
struct CryptoCoinRoute: Hashable {
    let coin: String
}

/// The Crypto page of the sidebar (Mac, iPad in regular width), inside the page column's stack.
struct CryptoSplitPage: View {
    var body: some View {
        CryptoPortfolioView()
            #if os(iOS)
            .navigationDestination(for: PhoneRoute.self) { route in
                switch route {
                case .cryptoCoin(let coin): CryptoCoinView(coin: coin)
                case .crypto: CryptoPortfolioView()
                case .item(let ref): ItemDetailView(ref: ref).id(ref)
                case .list(let filter): CategoryListView(filter: filter)
                case .watchtower(let title, let itemIDs): WatchtowerItemsList(title: title, itemIDs: itemIDs)
                case .duplicates: DuplicatesReviewView()
                }
            }
            #else
            .navigationDestination(for: CryptoCoinRoute.self) { route in
                CryptoCoinView(coin: route.coin)
            }
            #endif
    }
}
