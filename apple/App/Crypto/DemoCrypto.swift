#if DEBUG
import Foundation
import VaultKit

/// Demo data (Debug builds, `-OnePassDemoData YES`): the Crypto screen on recorded answers. The
/// demo account gets two wallets whose addresses come from public test vectors (the BIP39
/// "abandon … about" phrase, the EIP-55 example), the watch is switched on and every request is
/// answered here with fictional balances, prices and charts. Nothing goes out.
/// `-OnePassDemoCrypto NO` leaves the wallets without watch data and the watch off.
enum DemoCrypto {
    static var requested: Bool {
        guard DemoData.requested else { return false }
        return UserDefaults.standard.object(forKey: "OnePassDemoCrypto") == nil
            || UserDefaults.standard.bool(forKey: "OnePassDemoCrypto")
    }
    /// BIP39 test vector (all-0x7f entropy): a public, valid phrase. The core requires a phrase in
    /// every crypto wallet, so the watch-only demo wallet carries this one; it is never derived.
    static let watchOnlyPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"

    /// Bitcoin addresses of the demo zpub that carry coins (BIP84 vectors, receive 0 and 1).
    private static let bitcoin: [String: Int64] = [
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu": 12_500_000,
        "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g": 3_750_000,
    ]
    /// Ethereum balances per lower-case address: native wei, then token contract to raw amount.
    private static let ethereum: [String: (wei: UInt64, tokens: [String: UInt64])] = [
        "0x9858effd232b4033e47d90003d41ec34ecaeda94": (2_400_000_000_000_000_000, [
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": 1_200_000_000,
        ]),
        "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed": (850_000_000_000_000_000, [
            "0xdac17f958d2ee523a2206206994597c13d831ec7": 3_500_000_000,
            "0x514910771af9ca656af840dff83e8264ecf986ca": 12_000_000_000_000_000_000,
        ]),
    ]
    /// Fictional prices (any currency) and 24 h changes.
    private static let prices: [String: (Double, Double)] = [
        "bitcoin": (61_250.40, 1.84), "ethereum": (2_385.12, -2.31), "solana": (142.67, 4.92),
        "tether": (0.93, 0.01), "usd-coin": (0.93, -0.02), "chainlink": (11.84, -5.12),
        "dai": (0.93, 0.0), "wrapped-bitcoin": (61_180.00, 1.79), "uniswap": (6.42, 3.07),
    ]
    private static let market: [(String, String, String)] = [
        ("bitcoin", "btc", "Bitcoin"), ("ethereum", "eth", "Ethereum"), ("tether", "usdt", "Tether"),
        ("solana", "sol", "Solana"), ("usd-coin", "usdc", "USDC"), ("chainlink", "link", "Chainlink"),
        ("uniswap", "uni", "Uniswap"), ("dai", "dai", "Dai"),
    ]

    @MainActor
    static func installIfRequested(_ watch: CryptoWatch) {
        guard requested else {
            // `-OnePassDemoCrypto NO`: the demo's watch stays off (it is on by default) and asks nothing.
            if DemoData.requested, watch.isEnabled { watch.update { $0.choose(enabled: false) } }
            return
        }
        watch.useService(CryptoWatchService(http: RecordedCryptoHTTP(answer)))
        if !watch.isEnabled { watch.update { $0.enabled = true } }
    }

    /// The wallets of the demo account: the test phrase's public data (derived in the core), and a
    /// watch-only wallet with the EIP-55 example address (its phrase, a test vector, is not derived).
    @MainActor
    static func seed(_ session: VaultSession, vaultID: String, phraseWallet: FfiItem) async throws {
        guard requested else { return }
        _ = try await session.addDerivedWatchData(to: phraseWallet)
        var item = try session.newItem(type: .cryptoWallet, vaultID: vaultID)
        item.title = "Coffre long terme"
        item.set("name", .text(value: "Coffre long terme"))
        item.set("recovery_phrase", .mnemonic(value: watchOnlyPhrase))
        item.sections = CryptoWatchFields.adding("Ethereum, 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", to: item.sections)
        item.tags = ["Finance"]
        _ = try await session.save(ItemDraft(item: item).preparedForSave())
    }

    @Sendable
    static func answer(_ request: URLRequest) throws -> Data {
        guard let url = request.url, let host = url.host() else { throw URLError(.badURL) }
        if host == "mempool.space" || host == "blockstream.info" {
            let sats = bitcoin[url.lastPathComponent] ?? 0
            let used = sats > 0 ? 2 : 0
            return Data("""
            {"address":"\(url.lastPathComponent)","chain_stats":{"funded_txo_count":\(used),"funded_txo_sum":\(sats),\
            "spent_txo_count":0,"spent_txo_sum":0,"tx_count":\(used)},"mempool_stats":{"funded_txo_count":0,\
            "funded_txo_sum":0,"spent_txo_count":0,"spent_txo_sum":0,"tx_count":0}}
            """.utf8)
        }
        if host.contains("coingecko") { return try coingecko(url) }
        let calls = try JSONSerialization.jsonObject(with: request.httpBody ?? Data()) as? [[String: Any]] ?? []
        let out: [[String: Any]] = calls.map { c in
            let id = c["id"] ?? 0
            let params = c["params"] as? [Any] ?? []
            func ok(_ result: Any) -> [String: Any] { ["jsonrpc": "2.0", "id": id, "result": result] }
            switch c["method"] as? String {
            case "eth_getBalance":
                let a = (params.first as? String ?? "").lowercased()
                return ok(hex(ethereum[a]?.wei ?? 0))
            case "eth_call":
                let call = params.first as? [String: Any] ?? [:]
                let to = (call["to"] as? String ?? "").lowercased()
                let a = "0x" + String((call["data"] as? String ?? "").suffix(40)).lowercased()
                return ok(word(ethereum[a]?.tokens[to] ?? 0))
            case "getBalance":
                return ok(["context": ["slot": 1], "value": 18_400_000_000])
            case "getTokenAccountsByOwner":
                return ok(["context": ["slot": 1], "value": [
                    ["pubkey": "demo", "account": ["data": ["parsed": ["info": [
                        "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "owner": "demo",
                        "tokenAmount": ["amount": "250000000", "decimals": 6],
                    ], "type": "account"], "program": "spl-token"]]],
                ]])
            default:
                return ["jsonrpc": "2.0", "id": id, "error": ["code": -32601, "message": "unknown"]]
            }
        }
        return try JSONSerialization.data(withJSONObject: out)
    }

    private static func coingecko(_ url: URL) throws -> Data {
        let path = url.path()
        let query = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        func item(_ name: String) -> String { query.first { $0.name == name }?.value ?? "" }
        if path.hasSuffix("simple/price") {
            let currency = item("vs_currencies")
            var root: [String: Any] = [:]
            for coin in item("ids").split(separator: ",").map(String.init) {
                guard let (p, c) = prices[coin] else { continue }
                root[coin] = [currency: p, "\(currency)_24h_change": c]
            }
            return try JSONSerialization.data(withJSONObject: root)
        }
        if path.hasSuffix("market_chart") {
            let coin = url.deletingLastPathComponent().lastPathComponent
            let days = Double(item("days")) ?? 1
            return try JSONSerialization.data(withJSONObject: ["prices": chart(coin, days: days)])
        }
        if path.hasSuffix("coins/markets") {
            let list: [[String: Any]] = market.map { id, symbol, name in
                ["id": id, "symbol": symbol, "name": name, "current_price": prices[id]?.0 ?? 0,
                 "price_change_percentage_24h": prices[id]?.1 ?? 0]
            }
            return try JSONSerialization.data(withJSONObject: list)
        }
        throw URLError(.fileDoesNotExist)
    }

    /// A smooth made-up history that ends on the demo price, the same at every launch.
    private static func chart(_ coin: String, days: Double) -> [[Double]] {
        let (price, change) = prices[coin] ?? (1, 0)
        let n = 96
        let now = Date.now.timeIntervalSince1970 * 1000
        let span = days * 86_400_000
        let seed = Double(coin.unicodeScalars.reduce(0) { $0 + Int($1.value) })
        // Overall drift: the 24 h change for a day, a wider swing over longer periods.
        let drift = change / 100 * (days <= 1 ? 1 : min(6, days / 7 + 1))
        let start = price / (1 + drift)
        return (0..<n).map { i in
            let t = Double(i) / Double(n - 1)
            let wave = sin(t * 9 + seed) * 0.012 + sin(t * 23 + seed * 0.7) * 0.006
            let value = (start + (price - start) * t) * (1 + wave * (1 - t))
            return [now - span * (1 - t), i == n - 1 ? price : value]
        }
    }

    private static func hex(_ v: UInt64) -> String { "0x" + String(v, radix: 16) }

    private static func word(_ v: UInt64) -> String {
        let h = String(v, radix: 16)
        return "0x" + String(repeating: "0", count: 64 - h.count) + h
    }
}
#endif
