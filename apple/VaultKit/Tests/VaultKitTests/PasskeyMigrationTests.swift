import Compression
import Foundation
import Testing

@testable import VaultKit

/// "Passkeys restées dans 1Password": the 1PUX scan, the matching to the imported items, and the
/// per-account list that empties itself. Invented data only.
@MainActor
struct PasskeyMigrationTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    /// Three logins: one passkey without key (Atlas), one with its key (Borée, kept by the core),
    /// one in a section field without key (Cyan), plus a trashed one (never imported) and a note.
    static let exportData = """
        {"accounts":[{"attrs":{"name":"Camille"},"vaults":[{"attrs":{"uuid":"v1","name":"Personnel"},"items":[
          {"uuid":"a1","state":"active","categoryUuid":"001",
           "overview":{"title":"Exemple Atlas","url":"https://compte.atlas-fictif.fr/login"},
           "details":{"loginFields":[{"value":"motdepasse-fictif","designation":"password"}],
             "passkey":{"credentialId":"AQIDBA","rpId":"atlas-fictif.fr","userName":"camille"}}},
          {"uuid":"b1","state":"active","categoryUuid":"001",
           "overview":{"title":"Exemple Borée","url":"https://boree-fictif.fr"},
           "details":{"passkey":{"credentialId":"AQIDBA","privateKey":"AQIDBAUG","rpId":"boree-fictif.fr"}}},
          {"uuid":"c1","state":"active","categoryUuid":"001",
           "overview":{"title":"Exemple Cyan","urls":[{"url":"cyan-fictif.fr"}]},
           "details":{"sections":[{"fields":[{"id":"pk","value":{"Passkey":[{"credentialId":"AQID","username":"cam"}]}}]}]}},
          {"uuid":"t1","state":"trashed","categoryUuid":"001",
           "overview":{"title":"Exemple Corbeille"},
           "details":{"passkey":{"credentialId":"AQIDBA"}}},
          {"uuid":"n1","state":"active","categoryUuid":"003","overview":{"title":"Une note"},"details":{"notesPlain":"x"}},
          42
        ]}]}]}
        """

    // MARK: Scan

    @Test func scanListsKeylessPasskeysOnly() throws {
        for method in [ZipMethod.stored, .deflated] {
            let zip = try Self.zip([("export.attributes", Data("{}".utf8)), ("export.data", Data(Self.exportData.utf8))], method)
            let entries = PasskeyMigration.scan(format: "1pux", data: zip)
            #expect(entries == [
                .init(source: "v1/a1", title: "Exemple Atlas", url: "https://compte.atlas-fictif.fr/login", userName: "camille"),
                .init(source: "v1/c1", title: "Exemple Cyan", url: "cyan-fictif.fr", userName: "cam"),
            ], "\(method)")
        }
    }

    @Test func scanIgnoresOtherFormatsAndDamagedFiles() throws {
        let zip = try Self.zip([("export.data", Data(Self.exportData.utf8))], .stored)
        #expect(PasskeyMigration.scan(format: "cxf", data: zip).isEmpty)
        #expect(PasskeyMigration.scan(format: "1pux", data: Data("pas un zip".utf8)).isEmpty)
        #expect(PasskeyMigration.scan(format: "1pux", data: zip.prefix(zip.count - 10)).isEmpty)
        let noData = try Self.zip([("dir/export.data", Data(Self.exportData.utf8))], .stored)
        #expect(PasskeyMigration.scan(format: "1pux", data: noData).isEmpty)
        let badJSON = try Self.zip([("export.data", Data("{pas du json".utf8))], .deflated)
        #expect(PasskeyMigration.scan(format: "1pux", data: badJSON).isEmpty)
    }

    // MARK: Match

    @Test func matchPrefersItemsTheImportWrote() {
        let entries = [
            PasskeyMigration.Entry(source: "v/a", title: "Exemple Atlas", url: "https://atlas-fictif.fr/login", userName: ""),
            PasskeyMigration.Entry(source: "v/b", title: "Exemple Atlas", url: "atlas-fictif.fr", userName: ""),
            PasskeyMigration.Entry(source: "v/c", title: "Inconnu", url: nil, userName: ""),
        ]
        let before: [String: Int64] = ["old": 10]
        let after = [
            PasskeyMigration.Candidate(id: "old", title: "Exemple Atlas", primaryURL: "https://www.atlas-fictif.fr", updatedAt: 10),
            PasskeyMigration.Candidate(id: "new1", title: "exemple atlas", primaryURL: "https://atlas-fictif.fr/x", updatedAt: 99),
            PasskeyMigration.Candidate(id: "new2", title: "Exemple Atlas", primaryURL: "https://atlas-fictif.fr", updatedAt: 99),
            PasskeyMigration.Candidate(id: "other", title: "Exemple Atlas", primaryURL: "https://autre-fictif.fr", updatedAt: 99),
        ]
        #expect(PasskeyMigration.match(entries, before: before, after: after) == ["new1", "new2"])
    }

    @Test func matchFallsBackToTheOnlyVaultItem() {
        let entry = PasskeyMigration.Entry(source: "v/a", title: "Exemple Atlas", url: "atlas-fictif.fr", userName: "")
        let one = [PasskeyMigration.Candidate(id: "kept", title: "Exemple Atlas", primaryURL: "atlas-fictif.fr", updatedAt: 1)]
        // Unchanged by a re-import: not touched, but alone in the vault.
        #expect(PasskeyMigration.match([entry], before: ["kept": 1], after: one) == ["kept"])
        // Two untouched items fit: no guess.
        let two = one + [.init(id: "twin", title: "Exemple Atlas", primaryURL: "https://atlas-fictif.fr", updatedAt: 1)]
        #expect(PasskeyMigration.match([entry], before: ["kept": 1, "twin": 1], after: two).isEmpty)
        // Neither title nor address: never matched.
        let blank = PasskeyMigration.Entry(source: "v/x", title: " ", url: nil, userName: "")
        #expect(PasskeyMigration.match([blank], before: [:], after: one).isEmpty)
    }

    @Test func siteURLKeepsWebAddressesOnly() {
        #expect(PasskeyMigration.siteURL("https://compte.atlas-fictif.fr/login")?.absoluteString == "https://compte.atlas-fictif.fr/login")
        #expect(PasskeyMigration.siteURL("atlas-fictif.fr")?.absoluteString == "https://atlas-fictif.fr")
        #expect(PasskeyMigration.siteURL("javascript:alert(1)") == nil)
        #expect(PasskeyMigration.siteURL("ftp://atlas-fictif.fr") == nil)
        #expect(PasskeyMigration.siteURL("  ") == nil)
        #expect(PasskeyMigration.host("https://WWW.Atlas-Fictif.fr:8443/a") == "atlas-fictif.fr")
    }

    // MARK: Store

    @Test func storeKeepsIdsPerAccountAndEmptiesItself() throws {
        let suite = "PasskeyMigrationTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = PasskeyMigrationStore(defaults: defaults, accountID: "acct-1")
        store.add([.init(vaultID: "v", itemID: "a"), .init(vaultID: "v", itemID: "b"), .init(vaultID: "v", itemID: "gone")])
        #expect(PasskeyMigrationStore(defaults: defaults, accountID: "acct-2").refs.isEmpty, "one list per account")

        var a = Self.summary(id: "a", title: "Zeta")
        let b = Self.summary(id: "b", title: "Alpha")
        let trashed = Self.summary(id: "t", title: "T", trashed: true)
        store.add([.init(vaultID: "v", itemID: "t")])
        #expect(store.pending(in: [a, b, trashed]).map(\.id) == ["b", "a"], "title order, trash left out")

        a.passkeyCount = 1
        #expect(store.prune([a, b]) == 1)
        #expect(store.pending(in: [a, b]).map(\.id) == ["b"])
        #expect(store.refs.contains(.init(vaultID: "v", itemID: "gone")), "an item not listed now is kept")

        a.passkeyCount = 0
        #expect(store.pending(in: [a, b]).map(\.id) == ["b"], "a pruned item never comes back")
        store.remove(.init(vaultID: "v", itemID: "b"))
        store.remove(.init(vaultID: "v", itemID: "gone"))
        store.remove(.init(vaultID: "v", itemID: "t"))
        #expect(defaults.object(forKey: "onepass.passkeyMigration.acct-1") == nil, "an empty list leaves no key")
    }

    // MARK: End to end, through the core

    @Test func importedItemsAreFoundAndLeaveOnceTheyHoldAPasskey() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let vault = session.allVaults[0].id
        let zip = try Self.zip([("export.data", Data(Self.exportData.utf8))], .deflated)

        let preview = try await VaultSession.previewImport(format: "1pux", data: zip)
        #expect(PasskeyMigration.keylessCount(preview) == 2)
        let entries = PasskeyMigration.scan(format: "1pux", data: zip)
        #expect(entries.count == PasskeyMigration.keylessCount(preview), "the scan agrees with the core's count")

        let before = PasskeyMigration.snapshot(session.summaries, vaultID: vault)
        let done = try await session.importItems(format: "1pux", data: zip, vaultID: vault)
        #expect(PasskeyMigration.keylessCount(done) == 2)
        let after = session.summaries.filter { $0.vaultId == vault }.map(PasskeyMigration.Candidate.init)
        let ids = PasskeyMigration.match(entries, before: before, after: after)
        let titles = ids.compactMap { id in session.summaries.first { $0.id == id }?.title }
        #expect(titles == ["Exemple Atlas", "Exemple Cyan"])
        // Borée kept its passkey: the summary says so, it is not in the list.
        #expect(session.summaries.first { $0.title == "Exemple Borée" }?.passkeyCount == 1)
    }

    // MARK: Helpers

    enum ZipMethod { case stored, deflated }

    static func summary(id: String, title: String, trashed: Bool = false) -> FfiItemSummary {
        FfiItemSummary(
            id: id, vaultId: "v", itemType: .login, title: title, subtitle: "", favorite: false, tags: [],
            primaryUrl: nil, archived: false, trashedAt: trashed ? 1 : nil, createdAt: 0, updatedAt: 0)
    }

    /// A minimal zip: local headers, central directory, end. The core checks each CRC.
    static func zip(_ files: [(String, Data)], _ method: ZipMethod) throws -> Data {
        var out = Data()
        var central = Data()
        for (name, content) in files {
            let body = method == .stored ? content : try deflate(content)
            let offset = UInt32(out.count)
            let nameBytes = Data(name.utf8)
            let m: UInt16 = method == .stored ? 0 : 8
            let crc = crc32(content)
            // Built part by part: one long `+` chain is too slow for the type checker.
            let localParts: [Data] = [
                le32(0x0403_4B50), le16(20), le16(0), le16(m), le16(0), le16(0), le32(crc),
                le32(UInt32(body.count)), le32(UInt32(content.count)), le16(UInt16(nameBytes.count)), le16(0),
                nameBytes, body,
            ]
            let centralParts: [Data] = [
                le32(0x0201_4B50), le16(20), le16(20), le16(0), le16(m), le16(0), le16(0), le32(crc),
                le32(UInt32(body.count)), le32(UInt32(content.count)), le16(UInt16(nameBytes.count)),
                le16(0), le16(0), le16(0), le16(0), le32(0), le32(offset), nameBytes,
            ]
            localParts.forEach { out.append($0) }
            centralParts.forEach { central.append($0) }
        }
        let start = UInt32(out.count)
        out += central
        let endParts: [Data] = [
            le32(0x0605_4B50), le16(0), le16(0), le16(UInt16(files.count)), le16(UInt16(files.count)),
            le32(UInt32(central.count)), le32(start), le16(0),
        ]
        endParts.forEach { out.append($0) }
        return out
    }

    static func deflate(_ data: Data) throws -> Data {
        let capacity = data.count + 1024
        var out = Data(count: capacity)
        let n = out.withUnsafeMutableBytes { dst in
            data.withUnsafeBytes { src in
                compression_encode_buffer(
                    dst.bindMemory(to: UInt8.self).baseAddress!, capacity,
                    src.bindMemory(to: UInt8.self).baseAddress!, data.count, nil, COMPRESSION_ZLIB)
            }
        }
        try #require(n > 0)
        return out.prefix(n)
    }

    static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 { crc = crc & 1 == 1 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1 }
        }
        return ~crc
    }

    static func le16(_ v: UInt16) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }
    static func le32(_ v: UInt32) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }
}
