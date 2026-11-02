import Foundation

/// The one network door of the watch. The live one is an ephemeral session (no cookie, no cache,
/// no credential) with a size cap; tests and the demo answer from recorded responses.
public protocol CryptoHTTP: Sendable {
    func data(for request: URLRequest) async throws -> Data
}

public enum CryptoWatchError: Error, Equatable, Sendable {
    case http(Int)
    case tooLarge
    case badResponse(String)
}

public struct LiveCryptoHTTP: CryptoHTTP {
    /// Largest response read (a jsonParsed token list or a year of prices fits well under it).
    public static let maxBytes = 4 << 20
    private let session: URLSession

    public init() {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.urlCache = nil
        config.urlCredentialStorage = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 45
        // No identifier beyond the addresses: a generic agent, no language header.
        config.httpAdditionalHeaders = ["User-Agent": "OnePass", "Accept-Language": "en"]
        session = URLSession(configuration: config)
    }

    public func data(for request: URLRequest) async throws -> Data {
        let (data, response) = try await session.data(for: request)
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw CryptoWatchError.http(http.statusCode)
        }
        guard data.count <= Self.maxBytes else { throw CryptoWatchError.tooLarge }
        return data
    }
}

/// Test and demo double: answers with a closure.
public struct RecordedCryptoHTTP: CryptoHTTP {
    private let answer: @Sendable (URLRequest) throws -> Data

    public init(_ answer: @escaping @Sendable (URLRequest) throws -> Data) {
        self.answer = answer
    }

    public func data(for request: URLRequest) async throws -> Data {
        try answer(request)
    }
}

private func json(_ data: Data) throws -> Any {
    do {
        return try JSONSerialization.jsonObject(with: data)
    } catch {
        throw CryptoWatchError.badResponse("json")
    }
}

private func post(_ url: URL, _ body: Any) throws -> URLRequest {
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
    return request
}

/// Bitcoin over an Esplora REST API (mempool.space, Blockstream, or the user's own).
public enum EsploraAPI {
    public struct AddressStats: Equatable, Sendable {
        /// Confirmed plus unconfirmed balance, in satoshis.
        public var sats: Int64
        /// The address has history (confirmed or in the mempool): a gap-limit scan goes on.
        public var used: Bool
    }

    public static func request(base: URL, address: String) -> URLRequest {
        URLRequest(url: base.appending(path: "address").appending(path: address))
    }

    public static func parse(_ data: Data) throws -> AddressStats {
        guard let root = try json(data) as? [String: Any],
              let chain = root["chain_stats"] as? [String: Any]
        else { throw CryptoWatchError.badResponse("esplora") }
        let mempool = root["mempool_stats"] as? [String: Any] ?? [:]
        func int(_ d: [String: Any], _ k: String) -> Int64 { (d[k] as? NSNumber)?.int64Value ?? 0 }
        let sats = int(chain, "funded_txo_sum") - int(chain, "spent_txo_sum")
            + int(mempool, "funded_txo_sum") - int(mempool, "spent_txo_sum")
        let used = int(chain, "tx_count") + int(mempool, "tx_count") > 0
        return AddressStats(sats: sats, used: used)
    }
}

/// One JSON-RPC 2.0 call of a batch.
struct RPCCall {
    var method: String
    var params: [Any]
}

private func rpcBatch(_ calls: [RPCCall]) -> [[String: Any]] {
    calls.enumerated().map { i, c in ["jsonrpc": "2.0", "id": i, "method": c.method, "params": c.params] }
}

/// Results of a batch by id; an entry with an error is absent.
private func rpcResults(_ data: Data) throws -> [Int: Any] {
    let root = try json(data)
    let entries: [[String: Any]]
    if let list = root as? [[String: Any]] {
        entries = list
    } else if let one = root as? [String: Any] {
        entries = [one]
    } else {
        throw CryptoWatchError.badResponse("rpc")
    }
    var out: [Int: Any] = [:]
    for e in entries {
        guard let id = (e["id"] as? NSNumber)?.intValue, e["error"] == nil, let result = e["result"],
              !(result is NSNull)
        else { continue }
        out[id] = result
    }
    return out
}

/// Ethereum over JSON-RPC: `eth_getBalance` and the ERC-20 `balanceOf` of every catalog token, for
/// every address, in one batch.
public enum EVMAPI {
    public struct Query: Sendable {
        let request: URLRequest
        /// Call index to (address, asset id).
        let keys: [(address: String, asset: String)]
    }

    /// `balanceOf(address)` call data.
    public static func balanceOfData(_ address: String) -> String {
        let hex = address.lowercased().replacingOccurrences(of: "0x", with: "")
        return "0x70a08231" + String(repeating: "0", count: 24) + hex
    }

    public static func query(base: URL, addresses: [String], tokens: [CryptoAsset] = CryptoCatalog.tokens(.ethereum)) throws -> Query {
        var calls: [RPCCall] = []
        var keys: [(String, String)] = []
        let native = CryptoCatalog.native(.ethereum)
        for a in addresses {
            calls.append(RPCCall(method: "eth_getBalance", params: [a, "latest"]))
            keys.append((a, native.id))
            for t in tokens {
                guard let contract = t.contract else { continue }
                calls.append(RPCCall(method: "eth_call", params: [["to": contract, "data": balanceOfData(a)], "latest"]))
                keys.append((a, t.id))
            }
        }
        return Query(request: try post(base, rpcBatch(calls)), keys: keys)
    }

    /// Holdings (zero amounts left out) and the addresses whose native balance did not come back.
    public static func parse(_ data: Data, query: Query) throws -> (holdings: [CryptoAddressHolding], failed: [String]) {
        let results = try rpcResults(data)
        var holdings: [CryptoAddressHolding] = []
        var failed: [String] = []
        for (i, key) in query.keys.enumerated() {
            guard let asset = CryptoCatalog.asset(id: key.asset) else { continue }
            guard let hex = results[i] as? String,
                  let amount = CryptoAmount.decimal(hex: hex, decimals: asset.decimals)
            else {
                if asset.contract == nil { failed.append(key.address) }
                continue
            }
            if amount > 0 {
                holdings.append(CryptoAddressHolding(chain: .ethereum, address: key.address, asset: asset.id, amount: amount))
            }
        }
        return (holdings, failed)
    }
}

/// Solana over JSON-RPC: `getBalance` and the SPL token accounts (`jsonParsed`) of every address,
/// in one batch.
public enum SolanaAPI {
    static let tokenProgram = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

    public struct Query: Sendable {
        let request: URLRequest
        let addresses: [String]
    }

    public static func query(base: URL, addresses: [String]) throws -> Query {
        var calls: [RPCCall] = []
        for a in addresses {
            calls.append(RPCCall(method: "getBalance", params: [a]))
            calls.append(RPCCall(method: "getTokenAccountsByOwner",
                                 params: [a, ["programId": tokenProgram], ["encoding": "jsonParsed"]]))
        }
        return Query(request: try post(base, rpcBatch(calls)), addresses: addresses)
    }

    public static func parse(_ data: Data, query: Query) throws -> (holdings: [CryptoAddressHolding], failed: [String]) {
        let results = try rpcResults(data)
        let native = CryptoCatalog.native(.solana)
        let tokens = CryptoCatalog.tokens(.solana)
        var holdings: [CryptoAddressHolding] = []
        var failed: [String] = []
        for (n, address) in query.addresses.enumerated() {
            if let r = results[2 * n] as? [String: Any], let lamports = r["value"] as? NSNumber,
               let amount = CryptoAmount.decimal(integer: lamports.stringValue, decimals: native.decimals) {
                if amount > 0 {
                    holdings.append(CryptoAddressHolding(chain: .solana, address: address, asset: native.id, amount: amount))
                }
            } else {
                failed.append(address)
            }
            guard let r = results[2 * n + 1] as? [String: Any], let accounts = r["value"] as? [[String: Any]] else { continue }
            var sums: [String: Decimal] = [:]
            for acc in accounts {
                guard let info = ((acc["account"] as? [String: Any])?["data"] as? [String: Any])
                        .flatMap({ $0["parsed"] as? [String: Any] })?["info"] as? [String: Any],
                      let mint = info["mint"] as? String,
                      let token = tokens.first(where: { $0.contract == mint }),
                      let ta = info["tokenAmount"] as? [String: Any], let raw = ta["amount"] as? String,
                      let amount = CryptoAmount.decimal(integer: raw, decimals: token.decimals)
                else { continue }
                sums[token.id, default: 0] += amount
            }
            for (id, amount) in sums.sorted(by: { $0.key < $1.key }) where amount > 0 {
                holdings.append(CryptoAddressHolding(chain: .solana, address: address, asset: id, amount: amount))
            }
        }
        return (holdings, failed)
    }
}

/// Prices over a CoinGecko-compatible API (`simple/price`, `coins/{id}/market_chart`,
/// `coins/markets`). Only coin ids and the currency leave the device: never an address.
public enum PriceAPI {
    public static func priceRequest(base: URL, coins: [String], currency: String) -> URLRequest {
        var c = URLComponents(url: base.appending(path: "simple/price"), resolvingAgainstBaseURL: false)!
        c.queryItems = [
            URLQueryItem(name: "ids", value: coins.joined(separator: ",")),
            URLQueryItem(name: "vs_currencies", value: currency),
            URLQueryItem(name: "include_24hr_change", value: "true"),
        ]
        return URLRequest(url: c.url!)
    }

    public static func parsePrices(_ data: Data, currency: String) throws -> [String: CryptoPrice] {
        guard let root = try json(data) as? [String: Any] else { throw CryptoWatchError.badResponse("prices") }
        var out: [String: CryptoPrice] = [:]
        for (coin, value) in root {
            guard let d = value as? [String: Any], let p = d[currency] as? NSNumber else { continue }
            out[coin] = CryptoPrice(price: p.decimalValue, change24h: (d["\(currency)_24h_change"] as? NSNumber)?.doubleValue)
        }
        return out
    }

    public static func chartRequest(base: URL, coin: String, currency: String, period: CryptoPeriod) -> URLRequest {
        var c = URLComponents(url: base.appending(path: "coins").appending(path: coin).appending(path: "market_chart"),
                              resolvingAgainstBaseURL: false)!
        c.queryItems = [
            URLQueryItem(name: "vs_currency", value: currency),
            URLQueryItem(name: "days", value: String(period.days)),
        ]
        return URLRequest(url: c.url!)
    }

    /// At most `maxPoints` points, evenly picked (the last one kept).
    public static func parseChart(_ data: Data, maxPoints: Int = 120) throws -> [CryptoChartPoint] {
        guard let root = try json(data) as? [String: Any], let prices = root["prices"] as? [[NSNumber]] else {
            throw CryptoWatchError.badResponse("chart")
        }
        let points = prices.compactMap { pair -> CryptoChartPoint? in
            guard pair.count == 2 else { return nil }
            return CryptoChartPoint(date: Date(timeIntervalSince1970: pair[0].doubleValue / 1000), value: pair[1].doubleValue)
        }
        guard points.count > maxPoints, maxPoints > 1 else { return points }
        let step = Double(points.count - 1) / Double(maxPoints - 1)
        return (0..<maxPoints).map { points[Int((Double($0) * step).rounded())] }
    }

    public static func marketRequest(base: URL, currency: String, count: Int = 10) -> URLRequest {
        var c = URLComponents(url: base.appending(path: "coins/markets"), resolvingAgainstBaseURL: false)!
        c.queryItems = [
            URLQueryItem(name: "vs_currency", value: currency),
            URLQueryItem(name: "order", value: "market_cap_desc"),
            URLQueryItem(name: "per_page", value: String(count)),
            URLQueryItem(name: "page", value: "1"),
            URLQueryItem(name: "sparkline", value: "false"),
        ]
        return URLRequest(url: c.url!)
    }

    public static func parseMarket(_ data: Data) throws -> [CryptoMarketCoin] {
        guard let list = try json(data) as? [[String: Any]] else { throw CryptoWatchError.badResponse("market") }
        return list.compactMap { d in
            guard let id = d["id"] as? String, let symbol = d["symbol"] as? String, let name = d["name"] as? String,
                  let price = d["current_price"] as? NSNumber
            else { return nil }
            return CryptoMarketCoin(id: id, symbol: symbol.uppercased(), name: name, price: price.decimalValue,
                                    change24h: (d["price_change_percentage_24h"] as? NSNumber)?.doubleValue)
        }
    }
}
