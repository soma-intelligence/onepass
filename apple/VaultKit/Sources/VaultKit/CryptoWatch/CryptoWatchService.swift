import Foundation

/// One wallet item as the watch queries it: its public data only (from `Session.watchWallets`).
public struct CryptoWatchTarget: Sendable, Equatable {
    public var vaultID: String
    public var itemID: String
    public var title: String
    public var addresses: [(chain: CryptoChain, address: String)]
    public var xpub: String?

    public init(vaultID: String, itemID: String, title: String,
                addresses: [(chain: CryptoChain, address: String)], xpub: String?) {
        self.vaultID = vaultID
        self.itemID = itemID
        self.title = title
        self.addresses = addresses
        self.xpub = xpub
    }

    public init(_ w: FfiWalletWatch) {
        self.init(vaultID: w.vaultId, itemID: w.itemId, title: w.title,
                  addresses: w.addresses.map { (CryptoChain($0.chain), $0.address) }, xpub: w.xpub)
    }

    public var isEmpty: Bool { addresses.isEmpty && xpub == nil }

    public static func == (a: CryptoWatchTarget, b: CryptoWatchTarget) -> Bool {
        a.vaultID == b.vaultID && a.itemID == b.itemID && a.title == b.title && a.xpub == b.xpub
            && a.addresses.map(\.address) == b.addresses.map(\.address)
            && a.addresses.map(\.chain) == b.addresses.map(\.chain)
    }
}

/// Derives the addresses of an xpub. The live one calls the core; tests may inject.
public typealias XpubDeriver = @Sendable (_ xpub: String, _ change: Bool, _ start: UInt32, _ count: UInt32) throws -> [String]

/// Fetches balances and prices for a set of wallets, once, when asked (screen open or pull to
/// refresh): never in the background. Requests are batched per chain; only the addresses (to the
/// balance providers) and coin ids with the currency (to the price source) leave the device.
public struct CryptoWatchService: Sendable {
    public let http: any CryptoHTTP
    public let derive: XpubDeriver
    /// Esplora requests in flight at once (one per address).
    static let parallel = 4
    /// Gap limit of an xpub scan (BIP44).
    public let gapLimit: UInt32
    /// Highest index an xpub scan reaches per branch.
    static let scanCap: UInt32 = 1000

    public init(http: any CryptoHTTP = LiveCryptoHTTP(), gapLimit: UInt32 = 20,
                derive: @escaping XpubDeriver = { try watchXpubAddresses(xpub: $0, change: $1, start: $2, count: $3) }) {
        self.http = http
        self.gapLimit = gapLimit
        self.derive = derive
    }

    /// A full refresh. `previous` fills in what a failed request could not bring back (the last
    /// known amount of that address, the last prices and charts).
    public func refresh(
        targets: [CryptoWatchTarget], settings: CryptoWatchSettings, previous: CryptoSnapshot?, now: Date = .now
    ) async -> CryptoSnapshot {
        var wallets: [CryptoWalletBalance] = []
        let evm = Array(Set(targets.flatMap { $0.addresses.filter { $0.chain == .ethereum }.map(\.address) })).sorted()
        let sol = Array(Set(targets.flatMap { $0.addresses.filter { $0.chain == .solana }.map(\.address) })).sorted()
        let btc = Array(Set(targets.flatMap { $0.addresses.filter { $0.chain == .bitcoin }.map(\.address) })).sorted()

        async let evmResult = fetchEVM(evm, settings: settings)
        async let solResult = fetchSolana(sol, settings: settings)
        async let btcResult = fetchBitcoin(btc, settings: settings)
        let (e, s, b) = await (evmResult, solResult, btcResult)
        let byAddress = e.holdings + s.holdings + b.holdings
        let failedAddresses = Set(e.failed + s.failed + b.failed)
        let previousByItem = Dictionary((previous?.wallets ?? []).map { ($0.itemID, $0) }, uniquingKeysWith: { a, _ in a })

        for t in targets {
            var holdings: [CryptoAddressHolding] = []
            var failed: [String] = []
            let old = previousByItem[t.itemID]
            for (chain, address) in t.addresses {
                if failedAddresses.contains(address) {
                    failed.append(address)
                    holdings += old?.holdings.filter { $0.address == address && $0.chain == chain } ?? []
                } else {
                    holdings += byAddress.filter { $0.address == address && $0.chain == chain }
                }
            }
            var nextReceive: String?
            if let xpub = t.xpub {
                let scan = await scanXpub(xpub, settings: settings)
                if let sats = scan.sats {
                    if sats > 0 {
                        let asset = CryptoCatalog.native(.bitcoin)
                        holdings.append(CryptoAddressHolding(
                            chain: .bitcoin, address: xpub, asset: asset.id,
                            amount: CryptoAmount.scaled(Decimal(sats), decimals: asset.decimals), fromXpub: true))
                    }
                } else {
                    failed.append(xpub)
                    holdings += old?.holdings.filter { $0.address == xpub } ?? []
                }
                nextReceive = scan.nextReceive ?? old?.nextReceive
            }
            wallets.append(CryptoWalletBalance(vaultID: t.vaultID, itemID: t.itemID, title: t.title,
                                               holdings: holdings, failed: failed, nextReceive: nextReceive))
        }

        var prices = previous?.currency == settings.currency ? previous?.prices ?? [:] : [:]
        var charts = previous?.currency == settings.currency ? previous?.charts ?? [:] : [:]
        var market = previous?.currency == settings.currency ? previous?.market ?? [] : []
        if let base = settings.pricesURL {
            let held = Set(wallets.flatMap(\.holdings).compactMap { CryptoCatalog.asset(id: $0.asset)?.coin })
            // The tiles show Bitcoin and Ether even when not held.
            let coins = CryptoCatalog.coins.filter { held.contains($0) || $0 == "bitcoin" || $0 == "ethereum" }
            if let data = try? await http.data(for: PriceAPI.priceRequest(base: base, coins: coins, currency: settings.currency)),
               let parsed = try? PriceAPI.parsePrices(data, currency: settings.currency) {
                prices.merge(parsed) { _, new in new }
            }
            await withTaskGroup(of: (String, [CryptoChartPoint]?).self) { group in
                for coin in coins {
                    group.addTask {
                        let request = PriceAPI.chartRequest(base: base, coin: coin, currency: settings.currency, period: settings.period)
                        let points = try? PriceAPI.parseChart(await http.data(for: request))
                        return (coin, points)
                    }
                }
                for await (coin, points) in group {
                    if let points, !points.isEmpty { charts[coin, default: [:]][settings.period] = points }
                }
            }
            if !settings.hiddenSections.contains(.market),
               let data = try? await http.data(for: PriceAPI.marketRequest(base: base, currency: settings.currency)),
               let parsed = try? PriceAPI.parseMarket(data) {
                market = parsed
            }
        }
        return CryptoSnapshot(fetchedAt: now, currency: settings.currency, wallets: wallets,
                              prices: prices, charts: charts, market: market)
    }

    private func fetchEVM(_ addresses: [String], settings: CryptoWatchSettings) async -> (holdings: [CryptoAddressHolding], failed: [String]) {
        guard !addresses.isEmpty else { return ([], []) }
        do {
            let q = try EVMAPI.query(base: settings.baseURL(for: .ethereum), addresses: addresses)
            return try EVMAPI.parse(try await http.data(for: q.request), query: q)
        } catch {
            return ([], addresses)
        }
    }

    private func fetchSolana(_ addresses: [String], settings: CryptoWatchSettings) async -> (holdings: [CryptoAddressHolding], failed: [String]) {
        guard !addresses.isEmpty else { return ([], []) }
        do {
            let q = try SolanaAPI.query(base: settings.baseURL(for: .solana), addresses: addresses)
            return try SolanaAPI.parse(try await http.data(for: q.request), query: q)
        } catch {
            return ([], addresses)
        }
    }

    /// Esplora stats of each address, a few at a time; nil for a failed one.
    private func stats(_ addresses: [String], base: URL) async -> [String: EsploraAPI.AddressStats?] {
        var out: [String: EsploraAPI.AddressStats?] = [:]
        await withTaskGroup(of: (String, EsploraAPI.AddressStats?).self) { group in
            var next = addresses.makeIterator()
            func add() -> Bool {
                guard let a = next.next() else { return false }
                group.addTask {
                    (a, try? EsploraAPI.parse(await http.data(for: EsploraAPI.request(base: base, address: a))))
                }
                return true
            }
            for _ in 0..<Self.parallel where !add() { break }
            for await (a, s) in group {
                out[a] = s
                _ = add()
            }
        }
        return out
    }

    private func fetchBitcoin(_ addresses: [String], settings: CryptoWatchSettings) async -> (holdings: [CryptoAddressHolding], failed: [String]) {
        guard !addresses.isEmpty else { return ([], []) }
        let results = await stats(addresses, base: settings.baseURL(for: .bitcoin))
        let asset = CryptoCatalog.native(.bitcoin)
        var holdings: [CryptoAddressHolding] = []
        var failed: [String] = []
        for a in addresses {
            guard let s = results[a] ?? nil else {
                failed.append(a)
                continue
            }
            if s.sats > 0 {
                holdings.append(CryptoAddressHolding(chain: .bitcoin, address: a, asset: asset.id,
                                                     amount: CryptoAmount.scaled(Decimal(s.sats), decimals: asset.decimals)))
            }
        }
        return (holdings, failed)
    }

    /// Gap-limit scan of both branches of an account xpub: addresses are derived locally, a batch at
    /// a time, until `gapLimit` unused ones follow the last used one. `sats` nil when a request failed
    /// (the total would be wrong). `nextReceive` is the first unused receive address.
    public func scanXpub(_ xpub: String, settings: CryptoWatchSettings) async -> (sats: Int64?, nextReceive: String?) {
        let base = settings.baseURL(for: .bitcoin)
        var total: Int64 = 0
        var nextReceive: String?
        for change in [false, true] {
            var index: UInt32 = 0
            var lastUsed: Int64 = -1
            var firstUnused: String?
            while Int64(index) < lastUsed + 1 + Int64(gapLimit), index < Self.scanCap {
                let want = UInt32(lastUsed + 1 + Int64(gapLimit)) - index
                guard let batch = try? derive(xpub, change, index, min(want, Self.scanCap - index)), !batch.isEmpty else {
                    return (nil, nil)
                }
                let results = await stats(batch, base: base)
                for (offset, a) in batch.enumerated() {
                    guard let s = results[a] ?? nil else { return (nil, nil) }
                    total += s.sats
                    if s.used {
                        lastUsed = Int64(index) + Int64(offset)
                        firstUnused = nil
                    } else if firstUnused == nil {
                        firstUnused = a
                    }
                }
                index += UInt32(batch.count)
            }
            if !change { nextReceive = firstUnused }
        }
        return (total, nextReceive)
    }
}
