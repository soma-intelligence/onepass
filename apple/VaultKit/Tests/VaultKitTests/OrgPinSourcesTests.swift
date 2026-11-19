import Foundation
import Testing
import OnePassCore

@testable import VaultKit

private actor FakeDNS: DNSTXTResolver {
    private let answer: [String]
    private let delay: Duration?
    private(set) var asked: [(name: String, timeout: Duration)] = []

    init(_ answer: [String] = [], delay: Duration? = nil) {
        self.answer = answer
        self.delay = delay
    }

    func txtRecords(name: String, timeout: Duration) async -> [String] {
        asked.append((name, timeout))
        if let delay { try? await Task.sleep(for: delay) }
        return answer
    }

    var askedNames: [String] { asked.map(\.name) }
}

private func base32(_ data: Data) -> String {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    var out = ""
    var buffer = 0
    var bits = 0
    for byte in data {
        buffer = (buffer << 8) | Int(byte)
        bits += 8
        while bits >= 5 {
            out.append(alphabet[(buffer >> (bits - 5)) & 31])
            bits -= 5
        }
    }
    if bits > 0 { out.append(alphabet[(buffer << (5 - bits)) & 31]) }
    return out
}

private func fingerprint(_ byte: UInt8) -> Data { Data(repeating: byte, count: 32) }

private let server = "https://onepass.example.org"

private func invite(fingerprint: Data = fingerprint(1), domain: String? = nil) -> FfiOrgInvite {
    FfiOrgInvite(
        serverUrl: server, mailboxId: String(repeating: "a", count: 32),
        orgId: String(repeating: "b", count: 32), accountId: String(repeating: "c", count: 32),
        fingerprint: fingerprint, nonce: Data(repeating: 2, count: 32),
        credentialSeed: Data(repeating: 3, count: 32), memberToken: Data(repeating: 4, count: 32),
        domain: domain)
}

private func defaults(_ managed: [String: Any]?) -> UserDefaults {
    let suite = "OrgPinSourcesTests.\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: suite)!
    defaults.removePersistentDomain(forName: suite)
    if let managed { defaults.set(managed, forKey: ManagedOrgConfig.defaultsKey) }
    return defaults
}

@Suite("Org pin sources")
struct OrgPinSourcesTests {
    let goodFingerprint = base32(fingerprint(1))

    @Test func noManagedDictionaryReadsNone() {
        #expect(ManagedOrgConfig.read(defaults(nil), allowHTTP: false) == .none)
        #expect(ManagedOrgConfig.read(defaults(["other": "x"]), allowHTTP: false) == .none)
    }

    @Test func mdmWithBothKeysIsValid() {
        let reading = ManagedOrgConfig.read(
            defaults(["org_fpr": goodFingerprint, "server_url": server]), allowHTTP: false)
        #expect(reading == .valid(ManagedOrgConfig(serverURL: URL(string: server)!, fingerprint: fingerprint(1))))
    }

    @Test func mdmWithOnlyTheFingerprintIsInvalid() {
        #expect(ManagedOrgConfig.read(defaults(["org_fpr": goodFingerprint]), allowHTTP: false) == .invalid)
        #expect(ManagedOrgConfig.read(defaults(["server_url": server]), allowHTTP: false) == .invalid)
    }

    @Test func mdmWithHttpServerIsInvalid() {
        let reading = ManagedOrgConfig.read(
            defaults(["org_fpr": goodFingerprint, "server_url": "http://onepass.example.org"]), allowHTTP: false)
        #expect(reading == .invalid)
    }

    @Test func mdmWithUnparsableFingerprintIsInvalid() {
        let reading = ManagedOrgConfig.read(
            defaults(["org_fpr": "not a fingerprint", "server_url": server]), allowHTTP: false)
        #expect(reading == .invalid)
    }

    @Test func mdmForAnotherOrgRefusesTheInvite() async {
        let dns = FakeDNS([])
        let config = ManagedOrgConfig(serverURL: URL(string: server)!, fingerprint: fingerprint(9))
        let plan = await OrgPinResolver(mdm: .valid(config), dns: dns).plan(for: invite(domain: "example.org"))
        #expect(plan == .refuse(.mdmMismatch))
        let otherServer = ManagedOrgConfig(serverURL: URL(string: "https://other.example.org")!, fingerprint: fingerprint(1))
        #expect(await OrgPinResolver(mdm: .valid(otherServer), dns: dns).plan(for: invite()) == .refuse(.mdmMismatch))
        #expect(await dns.askedNames.isEmpty)
    }

    @Test func mdmMatchPinsFromMdm() async {
        let config = ManagedOrgConfig(serverURL: URL(string: server)!, fingerprint: fingerprint(1))
        let plan = await OrgPinResolver(mdm: .valid(config), dns: FakeDNS()).plan(for: invite())
        #expect(plan == .pin(source: .mdm, expected: fingerprint(1)))
    }

    @Test func mdmInvalidNeverFallsBackToTofu() async {
        let dns = FakeDNS()
        let plan = await OrgPinResolver(mdm: .invalid, dns: dns).plan(for: invite(domain: "example.org"))
        #expect(plan == .refuse(.mdmInvalid))
        #expect(await dns.askedNames.isEmpty)
    }

    @Test func dnsMatchPinsFromDNS() async {
        let dns = FakeDNS(["v=op1; org=\(goodFingerprint)"])
        let plan = await OrgPinResolver(mdm: .none, dns: dns).plan(for: invite(domain: "example.org"))
        #expect(plan == .pin(source: .dns, expected: fingerprint(1)))
        #expect(await dns.askedNames == ["_onepass.example.org"])
    }

    @Test func dnsDisagreementIsRefused() async {
        let other = base32(fingerprint(9))
        let two = FakeDNS(["v=op1; org=\(goodFingerprint)", "v=op1; org=\(other)"])
        #expect(await OrgPinResolver(mdm: .none, dns: two).plan(for: invite(domain: "example.org")) == .refuse(.dnsMismatch))
        let one = FakeDNS(["v=op1; org=\(other)"])
        #expect(await OrgPinResolver(mdm: .none, dns: one).plan(for: invite(domain: "example.org")) == .refuse(.dnsMismatch))
    }

    @Test func dnsDuplicatesOfTheSameValueStillMatch() async {
        let record = "v=op1; org=\(goodFingerprint)"
        let plan = await OrgPinResolver(mdm: .none, dns: FakeDNS([record, record, "unrelated"]))
            .plan(for: invite(domain: "example.org"))
        #expect(plan == .pin(source: .dns, expected: fingerprint(1)))
    }

    @Test func dnsSilenceOrTimeoutIsTofu() async {
        let dns = FakeDNS([], delay: .milliseconds(50))
        let resolver = OrgPinResolver(mdm: .none, dns: dns, timeout: .milliseconds(50))
        let plan = await resolver.plan(for: invite(domain: "example.org"))
        #expect(plan == .pin(source: .tofu(verified: false), expected: fingerprint(1)))
        #expect(await dns.asked.first?.timeout == .milliseconds(50))
        #expect(OrgPinResolver.dnsTimeout == .seconds(5))
        let junk = FakeDNS(["garbage"])
        #expect(await OrgPinResolver(mdm: .none, dns: junk).plan(for: invite(domain: "example.org"))
            == .pin(source: .tofu(verified: false), expected: fingerprint(1)))
    }

    @Test func noDomainIsTofuWithTheLinkFingerprint() async {
        let dns = FakeDNS(["v=op1; org=\(base32(fingerprint(9)))"])
        let plan = await OrgPinResolver(mdm: .none, dns: dns).plan(for: invite(fingerprint: fingerprint(5)))
        #expect(plan == .pin(source: .tofu(verified: false), expected: fingerprint(5)))
        #expect(await dns.askedNames.isEmpty)
    }

    @Test func txtRdataJoinsItsStrings() {
        #expect(SystemDNSTXTResolver.decodeTXT(Data([3, 0x61, 0x62, 0x63, 2, 0x64, 0x65])) == "abcde")
        #expect(SystemDNSTXTResolver.decodeTXT(Data([5, 0x61, 0x62])) == nil)
        #expect(SystemDNSTXTResolver.decodeTXT(Data()) == "")
    }
}

@Suite("System DNS collection")
struct SystemDNSCollectionTests {
    final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var value = 0
        func bump() { lock.lock(); value += 1; lock.unlock() }
        var count: Int { lock.lock(); defer { lock.unlock() }; return value }
    }

    @Test func aSilentQueryEndsAtTheTimeoutAndIsStoppedOnce() async {
        let stops = Counter()
        let started = ContinuousClock.now
        let records = await SystemDNSTXTResolver.gather(timeout: .milliseconds(100)) { _ in
            { stops.bump() }
        }
        #expect(records.isEmpty)
        #expect(ContinuousClock.now - started < .seconds(3))
        #expect(stops.count == 1)
    }

    @Test func theFirstFinalBatchWinsAndLaterOnesAreIgnored() async {
        let stops = Counter()
        let records = await SystemDNSTXTResolver.gather(timeout: .seconds(30)) { collector in
            collector.add("one")
            collector.add("two")
            collector.finish()
            collector.add("late")
            collector.finish()
            return { stops.bump() }
        }
        #expect(records == ["one", "two"])
        #expect(stops.count == 1)
    }

    @Test func cancellationEndsTheWait() async {
        let stops = Counter()
        let task = Task {
            await SystemDNSTXTResolver.gather(timeout: .seconds(30)) { _ in { stops.bump() } }
        }
        try? await Task.sleep(for: .milliseconds(50))
        task.cancel()
        #expect(await task.value.isEmpty)
        #expect(stops.count == 1)
    }

    @Test func aNameThatCannotExistGivesNoRecordsWithinTheTimeout() async {
        let records = await SystemDNSTXTResolver().txtRecords(name: "_onepass.nonexistent.invalid", timeout: .milliseconds(500))
        #expect(records.isEmpty)
    }
}
