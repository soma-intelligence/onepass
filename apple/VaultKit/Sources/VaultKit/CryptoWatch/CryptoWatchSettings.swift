import Foundation

/// Where balances or prices come from: a preset public service, or the user's own endpoint.
public enum CryptoEndpoint: Codable, Sendable, Hashable {
    case preset(String)
    case custom(URL)
}

/// One public service the user can pick.
public struct CryptoPreset: Sendable, Hashable, Identifiable {
    public let id: String
    public let name: String
    public let url: URL
}

public enum CryptoPresets {
    /// Esplora REST API.
    public static let bitcoin = [
        CryptoPreset(id: "mempool", name: "mempool.space", url: URL(string: "https://mempool.space/api")!),
        CryptoPreset(id: "blockstream", name: "Blockstream Esplora", url: URL(string: "https://blockstream.info/api")!),
    ]
    /// Ethereum JSON-RPC.
    public static let ethereum = [
        CryptoPreset(id: "publicnode", name: "PublicNode", url: URL(string: "https://ethereum-rpc.publicnode.com")!),
        CryptoPreset(id: "llamarpc", name: "LlamaRPC", url: URL(string: "https://eth.llamarpc.com")!),
    ]
    /// Solana JSON-RPC.
    public static let solana = [
        CryptoPreset(id: "solana", name: "Solana Foundation", url: URL(string: "https://api.mainnet-beta.solana.com")!),
        CryptoPreset(id: "publicnode", name: "PublicNode", url: URL(string: "https://solana-rpc.publicnode.com")!),
    ]
    /// CoinGecko-compatible price API.
    public static let prices = [
        CryptoPreset(id: "coingecko", name: "CoinGecko", url: URL(string: "https://api.coingecko.com/api/v3")!),
    ]

    public static func presets(for chain: CryptoChain) -> [CryptoPreset] {
        switch chain {
        case .bitcoin: bitcoin
        case .ethereum: ethereum
        case .solana: solana
        }
    }
}

/// Period of the charts and of the change shown under the total.
public enum CryptoPeriod: String, Codable, Sendable, CaseIterable, Hashable {
    case day, week, month, year

    /// `days` of the price source's history call.
    public var days: Int {
        switch self {
        case .day: 1
        case .week: 7
        case .month: 30
        case .year: 365
        }
    }
}

/// Cards of the Crypto screen the user can reorder or hide.
public enum CryptoSection: String, Codable, Sendable, CaseIterable, Hashable {
    case holdings, tiles, movers, market
}

/// Per-account settings of the watch. Kept in the encrypted watch file (custom endpoints may carry
/// an API key in their URL), never in `UserDefaults`.
public struct CryptoWatchSettings: Codable, Sendable, Equatable {
    /// Off by default: nothing leaves the device until the user turns it on.
    public var enabled = false
    /// Lower-case ISO 4217 code for prices.
    public var currency: String
    public var bitcoin: CryptoEndpoint = .preset("mempool")
    public var ethereum: CryptoEndpoint = .preset("publicnode")
    public var solana: CryptoEndpoint = .preset("solana")
    /// Nil: no prices (amounts only).
    public var prices: CryptoEndpoint? = .preset("coingecko")
    public var period: CryptoPeriod = .day
    public var sections: [CryptoSection] = CryptoSection.allCases
    public var hiddenSections: Set<CryptoSection> = []
    /// The user's own wallet app for "Ouvrir dans…": its URL scheme (`myWallet://`) and a name.
    public var handoffScheme: String?
    public var handoffName: String?

    public init(currency: String = CryptoWatchSettings.defaultCurrency) {
        self.currency = currency
    }

    /// Currencies the price source quotes and the picker offers.
    public static let currencies = ["eur", "usd", "gbp", "chf", "cad", "jpy", "aud"]

    /// The device's currency when the price source quotes it, else US dollars.
    public static var defaultCurrency: String {
        let code = Locale.current.currency?.identifier.lowercased() ?? "usd"
        return currencies.contains(code) ? code : "usd"
    }

    public func endpoint(for chain: CryptoChain) -> CryptoEndpoint {
        switch chain {
        case .bitcoin: bitcoin
        case .ethereum: ethereum
        case .solana: solana
        }
    }

    public mutating func setEndpoint(_ endpoint: CryptoEndpoint, for chain: CryptoChain) {
        switch chain {
        case .bitcoin: bitcoin = endpoint
        case .ethereum: ethereum = endpoint
        case .solana: solana = endpoint
        }
    }

    /// The base URL of an endpoint (a removed preset falls back to the first one).
    public static func url(_ endpoint: CryptoEndpoint, presets: [CryptoPreset]) -> URL {
        switch endpoint {
        case .custom(let url): url
        case .preset(let id): (presets.first { $0.id == id } ?? presets[0]).url
        }
    }

    public func baseURL(for chain: CryptoChain) -> URL {
        Self.url(endpoint(for: chain), presets: CryptoPresets.presets(for: chain))
    }

    public var pricesURL: URL? {
        prices.map { Self.url($0, presets: CryptoPresets.prices) }
    }

    /// The sections shown, in the user's order.
    public var visibleSections: [CryptoSection] {
        sections.filter { !hiddenSections.contains($0) }
    }

    /// A custom endpoint the watch accepts: HTTPS, or plain HTTP to a host on this network only
    /// (the user's own node: `localhost`, `*.local`, private IPv4). No user info in the URL.
    public static func acceptsCustom(_ url: URL) -> Bool {
        guard let host = url.host(percentEncoded: false)?.lowercased(), !host.isEmpty,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil
        else { return false }
        switch url.scheme?.lowercased() {
        case "https": return true
        case "http": return isLocal(host)
        default: return false
        }
    }

    static func isLocal(_ host: String) -> Bool {
        if host == "localhost" || host.hasSuffix(".local") || host == "127.0.0.1" || host == "::1" { return true }
        let parts = host.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4, parts.allSatisfy({ (0...255).contains($0) }) else { return false }
        return parts[0] == 10 || (parts[0] == 192 && parts[1] == 168) || (parts[0] == 172 && (16...31).contains(parts[1]))
    }
}

/// A price and its 24 h change, in the settings' currency.
public struct CryptoPrice: Codable, Sendable, Equatable {
    public var price: Decimal
    /// Percent (`-1.73` for -1.73 %), nil when the source does not say.
    public var change24h: Double?

    public init(price: Decimal, change24h: Double?) {
        self.price = price
        self.change24h = change24h
    }
}

public struct CryptoChartPoint: Codable, Sendable, Equatable, Hashable {
    public var date: Date
    public var value: Double

    public init(date: Date, value: Double) {
        self.date = date
        self.value = value
    }
}

/// One coin of the market list (no image: icons are bundled, never hotlinked).
public struct CryptoMarketCoin: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var symbol: String
    public var name: String
    public var price: Decimal
    public var change24h: Double?

    public init(id: String, symbol: String, name: String, price: Decimal, change24h: Double?) {
        self.id = id
        self.symbol = symbol
        self.name = name
        self.price = price
        self.change24h = change24h
    }
}

/// The amount of one asset at one address.
public struct CryptoAddressHolding: Codable, Sendable, Equatable, Hashable {
    public var chain: CryptoChain
    /// The address, or for an xpub the account key's label (`xpub` text shortened by the app).
    public var address: String
    /// `CryptoAsset.id`.
    public var asset: String
    public var amount: Decimal
    /// Set for balances summed over an xpub's derived addresses.
    public var fromXpub: Bool

    public init(chain: CryptoChain, address: String, asset: String, amount: Decimal, fromXpub: Bool = false) {
        self.chain = chain
        self.address = address
        self.asset = asset
        self.amount = amount
        self.fromXpub = fromXpub
    }
}

/// What the watch fetched for one wallet item.
public struct CryptoWalletBalance: Codable, Sendable, Equatable, Identifiable {
    public var id: String { itemID }
    public var vaultID: String
    public var itemID: String
    public var title: String
    public var holdings: [CryptoAddressHolding]
    /// Addresses (or xpubs) whose request failed: their last known amounts are kept.
    public var failed: [String]
    /// The first unused receive address of the xpub (the Receive sheet shows it).
    public var nextReceive: String?

    public init(vaultID: String, itemID: String, title: String, holdings: [CryptoAddressHolding],
                failed: [String] = [], nextReceive: String? = nil) {
        self.vaultID = vaultID
        self.itemID = itemID
        self.title = title
        self.holdings = holdings
        self.failed = failed
        self.nextReceive = nextReceive
    }
}

/// The last refresh: what the Crypto screen shows, and what stays (encrypted) for offline use.
public struct CryptoSnapshot: Codable, Sendable, Equatable {
    public var fetchedAt: Date
    public var currency: String
    public var wallets: [CryptoWalletBalance]
    /// Coin id to price.
    public var prices: [String: CryptoPrice]
    /// Coin id to history, per period.
    public var charts: [String: [CryptoPeriod: [CryptoChartPoint]]]
    public var market: [CryptoMarketCoin]

    public init(fetchedAt: Date, currency: String, wallets: [CryptoWalletBalance] = [],
                prices: [String: CryptoPrice] = [:], charts: [String: [CryptoPeriod: [CryptoChartPoint]]] = [:],
                market: [CryptoMarketCoin] = []) {
        self.fetchedAt = fetchedAt
        self.currency = currency
        self.wallets = wallets
        self.prices = prices
        self.charts = charts
        self.market = market
    }
}

/// Everything the encrypted watch file holds.
public struct CryptoWatchState: Codable, Sendable, Equatable {
    public var settings: CryptoWatchSettings
    public var snapshot: CryptoSnapshot?

    public init(settings: CryptoWatchSettings = CryptoWatchSettings(), snapshot: CryptoSnapshot? = nil) {
        self.settings = settings
        self.snapshot = snapshot
    }
}
