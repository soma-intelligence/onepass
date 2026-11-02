import Foundation
import Testing

@testable import VaultKit

/// Recorded provider responses (shapes of mempool.space, an Ethereum JSON-RPC node, the Solana
/// RPC and CoinGecko, values replaced by fictional ones). No test touches the network.
enum CryptoFixtures {
    static let esploraUsed = """
    {"address":"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu","chain_stats":{"funded_txo_count":2,"funded_txo_sum":150000,\
    "spent_txo_count":1,"spent_txo_sum":50000,"tx_count":3},"mempool_stats":{"funded_txo_count":1,"funded_txo_sum":2500,\
    "spent_txo_count":0,"spent_txo_sum":0,"tx_count":1}}
    """
    static let esploraEmpty = """
    {"address":"x","chain_stats":{"funded_txo_count":0,"funded_txo_sum":0,"spent_txo_count":0,"spent_txo_sum":0,"tx_count":0},\
    "mempool_stats":{"funded_txo_count":0,"funded_txo_sum":0,"spent_txo_count":0,"spent_txo_sum":0,"tx_count":0}}
    """
    static let prices = """
    {"bitcoin":{"eur":60000,"eur_24h_change":-1.5},"ethereum":{"eur":2000.5,"eur_24h_change":2.25},\
    "usd-coin":{"eur":0.92,"eur_24h_change":0.01},"solana":{"eur":150}}
    """
    static let chart = """
    {"prices":[[1730505600000,100.0],[1730509200000,110.0],[1730512800000,120.0]],"market_caps":[],"total_volumes":[]}
    """
    static let market = """
    [{"id":"bitcoin","symbol":"btc","name":"Bitcoin","image":"https://x/y.png","current_price":60000,\
    "price_change_percentage_24h":-1.5},{"id":"tether","symbol":"usdt","name":"Tether","current_price":0.92,\
    "price_change_percentage_24h":null}]
    """

    /// Answers an Ethereum batch: 1.5 ETH and 250 USDC for every address, nothing else.
    static func evm(_ request: URLRequest) throws -> Data {
        let calls = try JSONSerialization.jsonObject(with: request.httpBody!) as! [[String: Any]]
        let out: [[String: Any]] = calls.map { c in
            let id = c["id"]!
            if c["method"] as? String == "eth_getBalance" {
                return ["jsonrpc": "2.0", "id": id, "result": "0x14d1120d7b160000"] // 1.5e18
            }
            let to = ((c["params"] as! [Any])[0] as! [String: Any])["to"] as! String
            if to == "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" {
                return ["jsonrpc": "2.0", "id": id, "result": "0x" + String(repeating: "0", count: 56) + "0ee6b280"] // 250e6
            }
            if to == "0x6B175474E89094C44Da98b954EedeAC495271d0F" {
                return ["jsonrpc": "2.0", "id": id, "error": ["code": -32000, "message": "execution reverted"]]
            }
            return ["jsonrpc": "2.0", "id": id, "result": "0x" + String(repeating: "0", count: 64)]
        }
        return try JSONSerialization.data(withJSONObject: out)
    }

    /// Answers a Solana batch: 2.5 SOL and 10 USDC in two token accounts.
    static func solana(_ request: URLRequest) throws -> Data {
        let calls = try JSONSerialization.jsonObject(with: request.httpBody!) as! [[String: Any]]
        let out: [[String: Any]] = calls.map { c in
            let id = c["id"]!
            if c["method"] as? String == "getBalance" {
                return ["jsonrpc": "2.0", "id": id, "result": ["context": ["slot": 1], "value": 2_500_000_000]]
            }
            func account(_ mint: String, _ amount: String, _ decimals: Int) -> [String: Any] {
                ["pubkey": "x", "account": ["data": ["parsed": ["info": [
                    "mint": mint, "owner": "o",
                    "tokenAmount": ["amount": amount, "decimals": decimals, "uiAmountString": "?"],
                ], "type": "account"], "program": "spl-token"]]]
            }
            return ["jsonrpc": "2.0", "id": id, "result": ["context": ["slot": 1], "value": [
                account("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "4000000", 6),
                account("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "6000000", 6),
                account("So11111111111111111111111111111111111111112", "1", 9),
            ]]]
        }
        return try JSONSerialization.data(withJSONObject: out)
    }
}

@Suite("Crypto watch")
struct CryptoWatchTests {
    @Test func amountsFromHexAndIntegers() {
        #expect(CryptoAmount.decimal(hex: "0x14d1120d7b160000", decimals: 18) == Decimal(string: "1.5"))
        #expect(CryptoAmount.decimal(hex: "0x", decimals: 18) == 0)
        #expect(CryptoAmount.decimal(hex: "14d1", decimals: 0) == nil)
        #expect(CryptoAmount.decimal(hex: "0xzz", decimals: 0) == nil)
        #expect(CryptoAmount.decimal(integer: "2500000000", decimals: 9) == Decimal(string: "2.5"))
        #expect(CryptoAmount.decimal(integer: "-1", decimals: 0) == nil)
        // A full 256-bit word does not crash and stays positive.
        let big = CryptoAmount.decimal(hex: "0x" + String(repeating: "f", count: 64), decimals: 18)!
        #expect(big > 0)
    }

    @Test func esploraBalanceCountsTheMempool() throws {
        let s = try EsploraAPI.parse(Data(CryptoFixtures.esploraUsed.utf8))
        #expect(s.sats == 102_500)
        #expect(s.used)
        #expect(try !EsploraAPI.parse(Data(CryptoFixtures.esploraEmpty.utf8)).used)
        #expect(throws: CryptoWatchError.self) { try EsploraAPI.parse(Data("[]".utf8)) }
        let r = EsploraAPI.request(base: URL(string: "https://mempool.space/api")!, address: "bc1qabc")
        #expect(r.url?.absoluteString == "https://mempool.space/api/address/bc1qabc")
    }

    @Test func evmBatchParsesNativeAndTokensAndSkipsErrors() throws {
        let a = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        let q = try EVMAPI.query(base: URL(string: "https://rpc.example")!, addresses: [a])
        #expect(q.request.httpMethod == "POST")
        let body = String(decoding: q.request.httpBody!, as: UTF8.self)
        #expect(body.contains("0x70a08231000000000000000000000000" + "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"))
        let (holdings, failed) = try EVMAPI.parse(try CryptoFixtures.evm(q.request), query: q)
        #expect(failed.isEmpty)
        #expect(holdings.count == 2)
        #expect(holdings.first { $0.asset == "ethereum:native" }?.amount == Decimal(string: "1.5"))
        #expect(holdings.first { $0.asset.hasSuffix("eB48") }?.amount == 250)
    }

    @Test func evmMissingNativeResultMarksTheAddressFailed() throws {
        let q = try EVMAPI.query(base: URL(string: "https://rpc.example")!, addresses: ["0xabc"])
        let data = Data(#"[{"jsonrpc":"2.0","id":0,"error":{"code":-32005,"message":"rate limited"}}]"#.utf8)
        let (holdings, failed) = try EVMAPI.parse(data, query: q)
        #expect(holdings.isEmpty)
        #expect(failed == ["0xabc"])
    }

    @Test func solanaBatchSumsTokenAccountsOfKnownMints() throws {
        let q = try SolanaAPI.query(base: URL(string: "https://sol.example")!, addresses: ["Addr1"])
        let (holdings, failed) = try SolanaAPI.parse(try CryptoFixtures.solana(q.request), query: q)
        #expect(failed.isEmpty)
        #expect(holdings.first { $0.asset == "solana:native" }?.amount == Decimal(string: "2.5"))
        #expect(holdings.first { $0.asset.hasPrefix("solana:EPj") }?.amount == 10)
        #expect(holdings.count == 2)
    }

    @Test func pricesChartsAndMarket() throws {
        let prices = try PriceAPI.parsePrices(Data(CryptoFixtures.prices.utf8), currency: "eur")
        #expect(prices["bitcoin"] == CryptoPrice(price: 60000, change24h: -1.5))
        #expect(prices["solana"]?.change24h == nil)
        let chart = try PriceAPI.parseChart(Data(CryptoFixtures.chart.utf8))
        #expect(chart.map(\.value) == [100, 110, 120])
        #expect(try PriceAPI.parseChart(Data(CryptoFixtures.chart.utf8), maxPoints: 2).map(\.value) == [100, 120])
        let market = try PriceAPI.parseMarket(Data(CryptoFixtures.market.utf8))
        #expect(market.map(\.symbol) == ["BTC", "USDT"])
        #expect(market[1].change24h == nil)
        let r = PriceAPI.priceRequest(base: URL(string: "https://api.coingecko.com/api/v3")!, coins: ["bitcoin", "solana"], currency: "eur")
        #expect(r.url?.absoluteString == "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,solana&vs_currencies=eur&include_24hr_change=true")
    }

    @Test func customEndpointsMustBeHttpsOrLocal() {
        #expect(CryptoWatchSettings.acceptsCustom(URL(string: "https://eth.example/v2")!))
        #expect(CryptoWatchSettings.acceptsCustom(URL(string: "http://192.168.1.20:8332")!))
        #expect(CryptoWatchSettings.acceptsCustom(URL(string: "http://umbrel.local/api")!))
        #expect(!CryptoWatchSettings.acceptsCustom(URL(string: "http://eth.example")!))
        #expect(!CryptoWatchSettings.acceptsCustom(URL(string: "https://user:pw@eth.example")!))
        #expect(!CryptoWatchSettings.acceptsCustom(URL(string: "ftp://eth.example")!))
    }

    @Test func settingsAreOffByDefault() {
        let s = CryptoWatchSettings()
        #expect(!s.enabled)
        #expect(s.baseURL(for: .bitcoin).absoluteString == "https://mempool.space/api")
    }

    @Test func storeRoundTripsEncryptedAndRefusesTampering() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let keychain = InMemoryKeychain()
        let store = CryptoWatchStore(fileURL: dir.appending(path: "v.sqlite.cryptowatch"), keychain: keychain, accountID: "A")
        #expect(store.load() == CryptoWatchState())
        var state = CryptoWatchState()
        state.settings.enabled = true
        state.snapshot = CryptoSnapshot(
            fetchedAt: Date(timeIntervalSince1970: 1_000), currency: "eur",
            wallets: [CryptoWalletBalance(vaultID: "v", itemID: "i", title: "Froid", holdings: [
                CryptoAddressHolding(chain: .bitcoin, address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                                     asset: "bitcoin:native", amount: Decimal(string: "0.0125")!),
            ])],
            charts: ["bitcoin": [.week: [CryptoChartPoint(date: Date(timeIntervalSince1970: 5), value: 1)]]])
        try store.save(state)
        #expect(store.load() == state)
        let raw = try Data(contentsOf: store.fileURL)
        #expect(raw.range(of: Data("bc1qcr8te4kr".utf8)) == nil, "the address is not in clear")
        // Another account's id (associated data) does not open it.
        let other = CryptoWatchStore(fileURL: store.fileURL, keychain: keychain, accountID: "B")
        #expect(other.load() == CryptoWatchState())
        var flipped = raw
        flipped[flipped.count - 1] ^= 1
        try flipped.write(to: store.fileURL)
        #expect(store.load() == CryptoWatchState())
        store.erase()
        #expect(try keychain.read("cryptowatch.key.A") == nil)
    }

    @Test func xpubScanStopsAfterTheGapLimit() async {
        // Receive index 0 and 2 used, change index 0 used; everything else empty.
        let used: Set<String> = ["r0", "r2", "c0"]
        let http = RecordedCryptoHTTP { request in
            let address = request.url!.lastPathComponent
            return Data((used.contains(address) ? CryptoFixtures.esploraUsed : CryptoFixtures.esploraEmpty).utf8)
        }
        let asked = Counter()
        let service = CryptoWatchService(http: http, gapLimit: 3) { _, change, start, count in
            asked.add(Int(count))
            return (start..<start + count).map { (change ? "c" : "r") + String($0) }
        }
        var settings = CryptoWatchSettings()
        settings.enabled = true
        let scan = await service.scanXpub("xpub", settings: settings)
        #expect(scan.sats == Int64(307_500))
        #expect(scan.nextReceive == "r3")
        // Receive: 0..<3, then up to index 5 (last used 2 + gap 3); change: 0..<3, then 3.
        #expect(asked.value == 6 + 4)
    }

    @Test func refreshBuildsThePortfolioAndKeepsFailedAddressesFromThePreviousSnapshot() async throws {
        let failing = Flag()
        let http = RecordedCryptoHTTP { request in
            let url = request.url!.absoluteString
            if url.hasPrefix("https://mempool.space") {
                if failing.on { throw CryptoWatchError.http(503) }
                return Data(CryptoFixtures.esploraUsed.utf8)
            }
            if url.hasPrefix("https://ethereum-rpc") { return try CryptoFixtures.evm(request) }
            if url.hasPrefix("https://api.mainnet-beta") { return try CryptoFixtures.solana(request) }
            if url.contains("simple/price") { return Data(CryptoFixtures.prices.utf8) }
            if url.contains("market_chart") { return Data(CryptoFixtures.chart.utf8) }
            if url.contains("coins/markets") { return Data(CryptoFixtures.market.utf8) }
            throw CryptoWatchError.http(404)
        }
        let service = CryptoWatchService(http: http) { _, _, _, _ in [] }
        var settings = CryptoWatchSettings(currency: "eur")
        settings.enabled = true
        let target = CryptoWatchTarget(
            vaultID: "v", itemID: "i", title: "Ledger",
            addresses: [(.bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
                        (.ethereum, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
                        (.solana, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")],
            xpub: nil)
        let first = await service.refresh(targets: [target], settings: settings, previous: nil)
        #expect(first.wallets[0].failed.isEmpty)
        let p = CryptoPortfolio(snapshot: first, period: .day)
        let btc = try #require(p.holdings.first { $0.coin == "bitcoin" })
        #expect(btc.amount == Decimal(string: "0.001025"))
        #expect(btc.value == Decimal(string: "61.5"))
        // USDC on Ethereum (250) and Solana (10) is one holding.
        #expect(p.holdings.first { $0.coin == "usd-coin" }?.amount == 260)
        #expect(p.holdings.first { $0.coin == "usd-coin" }?.parts.count == 2)
        // Every coin's chart rises 100 to 120: the portfolio rises 20 %.
        #expect(abs((p.changePercent ?? 0) - 20) < 0.0001)
        #expect(first.market.count == 2)

        failing.on = true
        let second = await service.refresh(targets: [target], settings: settings, previous: first)
        #expect(second.wallets[0].failed == ["bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"])
        let kept = CryptoPortfolio(snapshot: second, period: .day)
        #expect(kept.holdings.first { $0.coin == "bitcoin" }?.amount == Decimal(string: "0.001025"))
    }

    @Test func noPriceSourceMeansAmountsOnlyAndNoPriceRequest() async {
        let priceCalls = Counter()
        let http = RecordedCryptoHTTP { request in
            if request.url!.host() == "api.coingecko.com" { priceCalls.add(1) }
            return Data(CryptoFixtures.esploraUsed.utf8)
        }
        var settings = CryptoWatchSettings()
        settings.enabled = true
        settings.prices = nil
        let service = CryptoWatchService(http: http) { _, _, _, _ in [] }
        let snap = await service.refresh(
            targets: [CryptoWatchTarget(vaultID: "v", itemID: "i", title: "t",
                                        addresses: [(.bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")], xpub: nil)],
            settings: settings, previous: nil)
        #expect(priceCalls.value == 0)
        let p = CryptoPortfolio(snapshot: snap, period: .day)
        #expect(p.total == 0 && p.hasUnpriced)
    }

    @MainActor
    @Test func watchStaysSilentWhileOffAndForgetsOnLock() async throws {
        let calls = Counter()
        let http = RecordedCryptoHTTP { _ in
            calls.add(1)
            return Data()
        }
        let watch = CryptoWatch(service: CryptoWatchService(http: http))
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        watch.open(store: CryptoWatchStore(fileURL: dir.appending(path: "x.cryptowatch"), keychain: InMemoryKeychain(), accountID: "A"))
        await watch.refresh()
        #expect(calls.value == 0)
        #expect(!watch.isEnabled)
        watch.update { $0.enabled = true }
        #expect(watch.isEnabled)
        watch.clear()
        #expect(!watch.isEnabled && watch.snapshot == nil)
    }
}

/// Thread-safe counters for the recorded providers.
final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func add(_ k: Int) { lock.withLock { n += k } }
    var value: Int { lock.withLock { n } }
}

final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var v = false
    var on: Bool {
        get { lock.withLock { v } }
        set { lock.withLock { v = newValue } }
    }
}

@Suite("Crypto watch fields")
struct CryptoWatchFieldsTests {
    static let derived = FfiWalletPublic(
        bitcoinZpub: "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        ethereumAddress: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        solanaAddress: "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk")

    private func values(_ id: String, _ sections: [FfiSection]) -> [String] {
        sections.flatMap(\.fields).filter { $0.id == id }.map(\.value.text)
    }

    @Test func mergesIntoAnEmptyTemplateOnce() {
        let empty = template(itemType: .cryptoWallet)
        let once = CryptoWatchFields.merging(Self.derived, into: empty)
        #expect(values("xpub", once) == [Self.derived.bitcoinZpub])
        #expect(values("public_addresses", once) == [
            "Ethereum, 0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "Solana, HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
        ])
        // Running it again adds nothing.
        #expect(CryptoWatchFields.merging(Self.derived, into: once) == once)
    }

    @Test func keepsAnXpubTheUserTypedAndAnEquivalentAddress() {
        var sections = template(itemType: .cryptoWallet)
        sections = CryptoWatchFields.adding("eth, 0x9858effd232b4033e47d90003d41ec34ecaeda94", to: sections)
        for s in sections.indices {
            for f in sections[s].fields.indices where sections[s].fields[f].id == "xpub" {
                sections[s].fields[f].value = .text(value: "xpub-of-the-user")
            }
        }
        let merged = CryptoWatchFields.merging(Self.derived, into: sections)
        #expect(values("xpub", merged) == ["xpub-of-the-user"])
        #expect(values("public_addresses", merged).count == 2)
    }
}
