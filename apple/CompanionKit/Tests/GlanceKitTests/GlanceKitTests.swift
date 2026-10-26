import Foundation
import Testing

@testable import GlanceKit

private let vaultHex = "0123456789abcdef0123456789abcdef"
private let itemHex = "fedcba9876543210fedcba9876543210"

private func item() -> GlanceItem {
    GlanceItem(
        vaultID: vaultHex, itemID: itemHex, title: "Camille Durand", symbol: "key.fill",
        tint: GlanceTint(red: 0.1, green: 0.2, blue: 0.3))
}

private func tempDir() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
}

private func snapshot(validUntil: Date) -> GlanceSnapshot {
    let now = Date(timeIntervalSince1970: 1_000_000)
    return GlanceSnapshot(
        generatedAt: now, validUntil: validUntil, favorites: [item()],
        codes: [
            GlanceCodes(
                item: item(), period: 30,
                codes: [GlanceCode(start: now, end: now.addingTimeInterval(30), code: "123456")])
        ])
}

@Suite struct GlanceKitTests {
    @Test func storeRoundTrip() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = GlanceStore(directory: dir.appendingPathComponent("Library/OnePass"))
        let snap = snapshot(validUntil: Date(timeIntervalSince1970: (Date.now.timeIntervalSince1970 + 600).rounded()))
        try store.write(snap)
        #expect(store.read() == snap)
        store.clear()
        #expect(store.read() == nil)
    }

    @Test func readRejectsCorruptExpiredMissing() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = GlanceStore(directory: dir)
        #expect(store.read() == nil)

        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data([0xde, 0xad, 0xbe, 0xef]).write(to: dir.appendingPathComponent("glance.json"))
        #expect(store.read() == nil)

        try store.write(snapshot(validUntil: Date.now.addingTimeInterval(-1)))
        #expect(store.read() == nil)
    }

    @Test func codeLookupByDate() {
        let start = Date(timeIntervalSince1970: 1_000)
        let codes = GlanceCodes(
            item: item(), period: 30,
            codes: [
                GlanceCode(start: start, end: start.addingTimeInterval(30), code: "111111"),
                GlanceCode(start: start.addingTimeInterval(30), end: start.addingTimeInterval(60), code: "222222"),
            ])
        #expect(codes.code(at: start)?.code == "111111")
        #expect(codes.code(at: start.addingTimeInterval(29.9))?.code == "111111")
        #expect(codes.code(at: start.addingTimeInterval(30))?.code == "222222")
        #expect(codes.code(at: start.addingTimeInterval(60)) == nil)
        #expect(codes.code(at: start.addingTimeInterval(-1)) == nil)
    }

    @Test func linkRoundTrip() {
        let links: [OnePassLink] = [.item(vaultID: vaultHex, itemID: itemHex), .generator, .search]
        for link in links { #expect(OnePassLink(url: link.url) == link) }
        #expect(item().link.url.absoluteString == "onepass://item?vault=\(vaultHex)&item=\(itemHex)")
    }

    @Test func linksRejectMalformedIDs() {
        let bad = [
            "onepass://item?vault=../x&item=\(itemHex)",
            "onepass://item?vault=\(vaultHex.uppercased())&item=\(itemHex)",
            "onepass://item?vault=\(vaultHex.dropLast())&item=\(itemHex)",
            "onepass://item?vault=\(vaultHex)",
            "onepass://other",
            "https://item?vault=\(vaultHex)&item=\(itemHex)",
        ]
        for s in bad { #expect(OnePassLink(url: URL(string: s)!) == nil, "\(s)") }
    }

    @Test func lockSignalPendingRules() {
        let name = "test.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let signal = LockSignal(defaults: defaults)
        let t = Date(timeIntervalSince1970: 5_000)
        #expect(signal.isPending(unlockedAt: nil) == false)
        #expect(signal.isPending(unlockedAt: t) == false)
        signal.request(at: t.addingTimeInterval(10))
        #expect(signal.isPending(unlockedAt: t))
        #expect(signal.isPending(unlockedAt: nil))
        #expect(signal.isPending(unlockedAt: t.addingTimeInterval(20)) == false)
    }

    @Test func lockSignalDarwinDelivery() async {
        let name = "test.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        await confirmation { confirmed in
            let stream = AsyncStream<Void> { continuation in
                let obs = LockSignal.observe { continuation.yield() }
                continuation.onTermination = { _ in obs.cancel() }
            }
            LockSignal(defaults: defaults).request()
            let received = await withTaskGroup(of: Bool.self) { group in
                group.addTask {
                    for await _ in stream { return true }
                    return false
                }
                group.addTask {
                    try? await Task.sleep(for: .seconds(2))
                    return false
                }
                let first = await group.next() ?? false
                group.cancelAll()
                return first
            }
            if received { confirmed() }
        }
    }
}
