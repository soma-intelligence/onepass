import Foundation

/// One coin across every watched wallet: what the holdings list shows.
public struct CryptoHolding: Sendable, Equatable, Identifiable {
    public var id: String { coin }
    public var coin: String
    public var symbol: String
    public var name: String
    public var amount: Decimal
    public var price: Decimal?
    /// Value in the snapshot's currency, nil without a price.
    public var value: Decimal?
    /// Percent change over the chosen period (24 h from the price source, longer periods from the
    /// chart), nil when unknown.
    public var change: Double?
    /// Per wallet item and address, largest first.
    public var parts: [Part]

    public struct Part: Sendable, Equatable, Hashable {
        public var itemID: String
        public var vaultID: String
        public var wallet: String
        public var chain: CryptoChain
        public var address: String
        public var amount: Decimal
        public var fromXpub: Bool
    }
}

/// One wallet item's total, for the group cards.
public struct CryptoWalletTotal: Sendable, Equatable, Identifiable {
    public var id: String { itemID }
    public var itemID: String
    public var vaultID: String
    public var title: String
    public var value: Decimal
    public var change: Double?
    public var holdings: [CryptoHolding]
}

/// What the Crypto screen draws from a snapshot, for one period.
public struct CryptoPortfolio: Sendable, Equatable {
    public var currency: String
    public var total: Decimal
    /// Absolute change over the period, nil when no history is known.
    public var changeValue: Decimal?
    public var changePercent: Double?
    /// Sum of each held coin's amount times its price over the period (today's amounts).
    public var history: [CryptoChartPoint]
    public var holdings: [CryptoHolding]
    public var wallets: [CryptoWalletTotal]
    /// Some amounts are not valued (no price): the total leaves them out.
    public var hasUnpriced: Bool

    public init(snapshot: CryptoSnapshot, period: CryptoPeriod) {
        currency = snapshot.currency
        holdings = Self.holdings(of: snapshot.wallets, snapshot: snapshot, period: period)
        total = holdings.compactMap(\.value).reduce(0, +)
        hasUnpriced = holdings.contains { $0.value == nil }
        history = Self.history(holdings, snapshot: snapshot, period: period)
        if let first = history.first?.value, let last = history.last?.value, first > 0 {
            changeValue = Decimal(last - first)
            changePercent = (last - first) / first * 100
        } else if period == .day {
            // No chart: the 24 h change of each priced coin, weighted by value.
            let weighted = holdings.compactMap { h -> (Double, Double)? in
                guard let v = h.value, let c = h.change else { return nil }
                return (NSDecimalNumber(decimal: v).doubleValue, c)
            }
            let now = weighted.reduce(0) { $0 + $1.0 }
            let before = weighted.reduce(0) { $0 + $1.0 / (1 + $1.1 / 100) }
            if before > 0 {
                changeValue = Decimal(now - before)
                changePercent = (now - before) / before * 100
            }
        }
        wallets = snapshot.wallets.map { w in
            let hs = Self.holdings(of: [w], snapshot: snapshot, period: period)
            let value = hs.compactMap(\.value).reduce(0, +)
            let hist = Self.history(hs, snapshot: snapshot, period: period)
            var change: Double?
            if let f = hist.first?.value, let l = hist.last?.value, f > 0 { change = (l - f) / f * 100 }
            return CryptoWalletTotal(itemID: w.itemID, vaultID: w.vaultID, title: w.title, value: value,
                                     change: change, holdings: hs)
        }
        .sorted { $0.value > $1.value }
    }

    static func change(coin: String, snapshot: CryptoSnapshot, period: CryptoPeriod) -> Double? {
        if let points = snapshot.charts[coin]?[period], let f = points.first?.value, let l = points.last?.value, f > 0 {
            return (l - f) / f * 100
        }
        return period == .day ? snapshot.prices[coin]?.change24h : nil
    }

    static func holdings(of wallets: [CryptoWalletBalance], snapshot: CryptoSnapshot, period: CryptoPeriod) -> [CryptoHolding] {
        var byCoin: [String: CryptoHolding] = [:]
        for w in wallets {
            for h in w.holdings {
                guard let asset = CryptoCatalog.asset(id: h.asset) else { continue }
                let part = CryptoHolding.Part(itemID: w.itemID, vaultID: w.vaultID, wallet: w.title, chain: h.chain,
                                              address: h.address, amount: h.amount, fromXpub: h.fromXpub)
                byCoin[asset.coin, default: CryptoHolding(
                    coin: asset.coin, symbol: asset.symbol, name: CryptoCatalog.coin(asset.coin)?.name ?? asset.name,
                    amount: 0, price: nil, value: nil, change: nil, parts: [])].parts.append(part)
                byCoin[asset.coin]!.amount += h.amount
            }
        }
        return byCoin.values.map { h in
            var h = h
            h.parts.sort { $0.amount > $1.amount }
            if let p = snapshot.prices[h.coin]?.price {
                h.price = p
                h.value = h.amount * p
            }
            h.change = change(coin: h.coin, snapshot: snapshot, period: period)
            return h
        }
        .sorted { ($0.value ?? -1, $0.name) > ($1.value ?? -1, $1.name) }
    }

    /// The portfolio's value over the period: each coin's chart (resampled on the densest chart's
    /// dates) times today's amount.
    static func history(_ holdings: [CryptoHolding], snapshot: CryptoSnapshot, period: CryptoPeriod) -> [CryptoChartPoint] {
        let series = holdings.compactMap { h -> ([CryptoChartPoint], Double)? in
            guard let points = snapshot.charts[h.coin]?[period], !points.isEmpty else { return nil }
            return (points, NSDecimalNumber(decimal: h.amount).doubleValue)
        }
        guard let axis = series.max(by: { $0.0.count < $1.0.count })?.0 else { return [] }
        return axis.map { p in
            let sum = series.reduce(0.0) { acc, s in acc + Self.value(at: p.date, in: s.0) * s.1 }
            return CryptoChartPoint(date: p.date, value: sum)
        }
    }

    /// The last point at or before `date` (the first one before the series starts).
    static func value(at date: Date, in points: [CryptoChartPoint]) -> Double {
        var lo = 0, hi = points.count - 1
        if date <= points[0].date { return points[0].value }
        while lo < hi {
            let mid = (lo + hi + 1) / 2
            if points[mid].date <= date { lo = mid } else { hi = mid - 1 }
        }
        return points[lo].value
    }
}
