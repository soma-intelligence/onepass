import Foundation
import OnePassCore
import Testing

@testable import VaultKit

/// Open and sign in (`OpenAndSignIn`): what a tap on a login's website records and opens. The
/// recorder is the real Rust one (`record_pending_sign_in`), on a temporary folder.
@Suite("Open and sign in")
struct OpenAndSignInTests {
    let itemID = "0123456789abcdef0123456789abcdef"

    func folder() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("onepass-open-sign-in-\(UUID().uuidString)")
    }

    func entry(_ folder: URL) throws -> [String: Any] {
        let data = try Data(contentsOf: folder.appendingPathComponent("pending-sign-in.json"))
        return try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    @Test func pageURLsAreWebPagesOnly() {
        #expect(OpenAndSignIn.pageURL("accounts.google.com")?.absoluteString == "https://accounts.google.com")
        #expect(OpenAndSignIn.pageURL(" https://atlas-cloud.test/login ")?.host() == "atlas-cloud.test")
        #expect(OpenAndSignIn.pageURL("http://atlas-cloud.test")?.scheme == "http")
        #expect(OpenAndSignIn.pageURL("javascript:alert(1)") == nil)
        #expect(OpenAndSignIn.pageURL("file:///etc/hosts") == nil)
        #expect(OpenAndSignIn.pageURL("") == nil)
    }

    @Test func httpsRecordsTheItemAndTheSiteOnly() throws {
        let dir = folder()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = OpenAndSignIn.prepare(itemID: itemID, rawURL: "https://accounts.google.com/signin", folder: dir)
        #expect(out == .signIn(URL(string: "https://accounts.google.com/signin")!))
        let e = try entry(dir)
        #expect(e["site"] as? String == "google.com")
        #expect(e["host"] as? String == "accounts.google.com")
        #expect(e["item_id"] as? String == "01234567-89ab-cdef-0123-456789abcdef")
        let created = try #require(e["created"] as? Int)
        let expires = try #require(e["expires"] as? Int)
        #expect(expires - created == Int(OpenAndSignIn.ttl))
        // Never a value: these keys and nothing else.
        #expect(Set(e.keys) == ["v", "item_id", "site", "host", "created", "expires"])
        let mode = try FileManager.default.attributesOfItem(
            atPath: dir.appendingPathComponent("pending-sign-in.json").path)[.posixPermissions] as? Int
        #expect(mode == 0o600)
    }

    @Test func httpOpensWithoutSignIn() {
        let dir = folder()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = OpenAndSignIn.prepare(itemID: itemID, rawURL: "http://atlas-cloud.test", folder: dir)
        #expect(out == .openOnly(URL(string: "http://atlas-cloud.test")!))
        #expect(!FileManager.default.fileExists(atPath: dir.appendingPathComponent("pending-sign-in.json").path))
    }

    @Test func notAWebPageDoesNothing() {
        #expect(OpenAndSignIn.prepare(itemID: itemID, rawURL: "ssh://host", folder: folder()) == nil)
    }

    @Test func aFailedRecordStillOpens() {
        struct Boom: Error {}
        let out = OpenAndSignIn.prepare(itemID: itemID, rawURL: "atlas-cloud.test", folder: folder()) { _, _, _ in
            throw Boom()
        }
        #expect(out == .openOnly(URL(string: "https://atlas-cloud.test")!))
    }

    @Test func cancelDropsThePendingSignIn() {
        let dir = folder()
        defer { try? FileManager.default.removeItem(at: dir) }
        _ = OpenAndSignIn.prepare(itemID: itemID, rawURL: "atlas-cloud.test", folder: dir)
        OpenAndSignIn.cancel(folder: dir)
        #expect(!FileManager.default.fileExists(atPath: dir.appendingPathComponent("pending-sign-in.json").path))
    }

    @Test func aNewTapReplacesTheOldOne() throws {
        let dir = folder()
        defer { try? FileManager.default.removeItem(at: dir) }
        _ = OpenAndSignIn.prepare(itemID: itemID, rawURL: "atlas-cloud.test", folder: dir)
        _ = OpenAndSignIn.prepare(itemID: "ffffffffffffffffffffffffffffffff", rawURL: "accounts.google.com", folder: dir)
        #expect(try entry(dir)["site"] as? String == "google.com")
    }

    @Test func safariExtensionPairedOnlyWithASafariPairing() {
        let keychain = InMemoryKeychain()
        #expect(!OpenAndSignIn.safariExtensionPaired(keychain: keychain))
        let store = BridgePairingStore(keychain: keychain)
        store.add(
            FfiBridgePairing(
                pairingId: "aa", key: Data(repeating: 1, count: 32), extName: "OnePass", browser: "Chrome",
                extensionId: "abc", verifiedBrowser: "", createdAt: 1, lastUsed: 1))
        #expect(!OpenAndSignIn.safariExtensionPaired(keychain: keychain))
        store.add(
            FfiBridgePairing(
                pairingId: "bb", key: Data(repeating: 2, count: 32), extName: "OnePass", browser: "Safari",
                extensionId: "safari", verifiedBrowser: "Safari", createdAt: 1, lastUsed: 1))
        #expect(OpenAndSignIn.safariExtensionPaired(keychain: keychain))
    }
}
