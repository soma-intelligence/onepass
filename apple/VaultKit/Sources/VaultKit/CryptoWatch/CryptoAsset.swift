import Foundation

/// Chains the watch supports (spec 2026-11-02-crypto-watch). New chains add a case, their assets
/// and a provider; EVM networks reuse the Ethereum provider with another endpoint.
public enum CryptoChain: String, Codable, Sendable, CaseIterable, Hashable {
    case bitcoin, ethereum, solana

    public init(_ ffi: FfiWatchChain) {
        switch ffi {
        case .bitcoin: self = .bitcoin
        case .ethereum: self = .ethereum
        case .solana: self = .solana
        }
    }

    public var ffi: FfiWatchChain {
        switch self {
        case .bitcoin: .bitcoin
        case .ethereum: .ethereum
        case .solana: .solana
        }
    }

    /// Network name, never translated.
    public var name: String {
        switch self {
        case .bitcoin: "Bitcoin"
        case .ethereum: "Ethereum"
        case .solana: "Solana"
        }
    }

    public var native: CryptoAsset { CryptoCatalog.native(self) }
}

/// One asset on one chain: the native coin, an ERC-20 contract or an SPL mint.
public struct CryptoAsset: Codable, Sendable, Hashable, Identifiable {
    /// `<chain>:<contract or "native">`: unique per chain.
    public var id: String { "\(chain.rawValue):\(contract ?? "native")" }
    /// Identifier of the coin at the price source (CoinGecko ids): the same coin on two chains
    /// (USDC on Ethereum and on Solana) shares it and is shown as one holding.
    public let coin: String
    public let symbol: String
    public let name: String
    public let chain: CryptoChain
    public let decimals: Int
    /// ERC-20 contract (EIP-55) or SPL mint; nil for the native coin.
    public let contract: String?

    public init(coin: String, symbol: String, name: String, chain: CryptoChain, decimals: Int, contract: String?) {
        self.coin = coin
        self.symbol = symbol
        self.name = name
        self.chain = chain
        self.decimals = decimals
        self.contract = contract
    }
}

/// The assets the watch looks for. Tokens are the most held ones; a token outside this list is
/// not queried (each one is a request the provider sees).
public enum CryptoCatalog {
    public static let all: [CryptoAsset] = [
        CryptoAsset(coin: "bitcoin", symbol: "BTC", name: "Bitcoin", chain: .bitcoin, decimals: 8, contract: nil),
        CryptoAsset(coin: "ethereum", symbol: "ETH", name: "Ether", chain: .ethereum, decimals: 18, contract: nil),
        CryptoAsset(coin: "solana", symbol: "SOL", name: "Solana", chain: .solana, decimals: 9, contract: nil),
        // ERC-20 (Ethereum mainnet contracts).
        CryptoAsset(coin: "tether", symbol: "USDT", name: "Tether", chain: .ethereum, decimals: 6,
                    contract: "0xdAC17F958D2ee523a2206206994597C13D831ec7"),
        CryptoAsset(coin: "usd-coin", symbol: "USDC", name: "USD Coin", chain: .ethereum, decimals: 6,
                    contract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        CryptoAsset(coin: "dai", symbol: "DAI", name: "Dai", chain: .ethereum, decimals: 18,
                    contract: "0x6B175474E89094C44Da98b954EedeAC495271d0F"),
        CryptoAsset(coin: "wrapped-bitcoin", symbol: "WBTC", name: "Wrapped Bitcoin", chain: .ethereum, decimals: 8,
                    contract: "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"),
        CryptoAsset(coin: "chainlink", symbol: "LINK", name: "Chainlink", chain: .ethereum, decimals: 18,
                    contract: "0x514910771AF9Ca656af840dff83E8264EcF986CA"),
        CryptoAsset(coin: "uniswap", symbol: "UNI", name: "Uniswap", chain: .ethereum, decimals: 18,
                    contract: "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984"),
        // SPL tokens (Solana mints).
        CryptoAsset(coin: "usd-coin", symbol: "USDC", name: "USD Coin", chain: .solana, decimals: 6,
                    contract: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
        CryptoAsset(coin: "tether", symbol: "USDT", name: "Tether", chain: .solana, decimals: 6,
                    contract: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"),
    ]

    public static func native(_ chain: CryptoChain) -> CryptoAsset {
        all.first { $0.chain == chain && $0.contract == nil }!
    }

    public static func tokens(_ chain: CryptoChain) -> [CryptoAsset] {
        all.filter { $0.chain == chain && $0.contract != nil }
    }

    public static func asset(id: String) -> CryptoAsset? {
        all.first { $0.id == id }
    }

    /// The first asset of a coin (its name and symbol).
    public static func coin(_ coin: String) -> CryptoAsset? {
        all.first { $0.coin == coin }
    }

    /// Every coin id, in catalog order, once.
    public static var coins: [String] {
        var seen = Set<String>()
        return all.map(\.coin).filter { seen.insert($0).inserted }
    }
}

/// Exact decimal amounts from the integer strings providers return.
public enum CryptoAmount {
    /// `value / 10^decimals` for a non-negative integer in base 10. Nil for anything else.
    public static func decimal(integer text: String, decimals: Int) -> Decimal? {
        let digits = text.trimmingCharacters(in: .whitespaces)
        guard !digits.isEmpty, digits.utf8.allSatisfy({ (48...57).contains($0) }),
              let value = Decimal(string: digits, locale: Locale(identifier: "en_US_POSIX"))
        else { return nil }
        return scaled(value, decimals: decimals)
    }

    /// `value / 10^decimals` for a `0x` hex quantity (JSON-RPC). Nil for anything else. Values past
    /// 38 significant digits lose their last digits (far below any displayed precision).
    public static func decimal(hex text: String, decimals: Int) -> Decimal? {
        guard text.hasPrefix("0x") || text.hasPrefix("0X") else { return nil }
        let body = text.dropFirst(2)
        if body.isEmpty { return 0 }
        guard body.count <= 64 else { return nil }
        var value = Decimal(0)
        for c in body {
            guard let d = c.hexDigitValue else { return nil }
            value = value * 16 + Decimal(d)
        }
        return scaled(value, decimals: decimals)
    }

    static func scaled(_ value: Decimal, decimals: Int) -> Decimal {
        guard decimals > 0 else { return value }
        var divisor = Decimal(1)
        for _ in 0..<decimals { divisor *= 10 }
        return value / divisor
    }
}
