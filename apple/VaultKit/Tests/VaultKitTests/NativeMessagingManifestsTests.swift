#if os(macOS)
import Foundation
import Testing

@testable import VaultKit

@Suite("Native messaging manifests")
struct NativeMessagingManifestsTests {
    static let chromeID = "abcdefghijklmnopabcdefghijklmnop"
    static let firefoxID = "onepass@somalabs.me"

    /// A home with the given browser support folders, and a relay file.
    struct Home {
        let root: URL
        let relay: URL

        init(browsers: [String]) throws {
            root = FileManager.default.temporaryDirectory.appendingPathComponent("nmh-\(UUID().uuidString)")
            let support = root.appendingPathComponent("Library/Application Support")
            for dir in browsers {
                try FileManager.default.createDirectory(
                    at: support.appendingPathComponent(dir), withIntermediateDirectories: true)
            }
            relay = root.appendingPathComponent("OnePass.app/Contents/Helpers/onepass-relay")
            try FileManager.default.createDirectory(
                at: relay.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data("#!".utf8).write(to: relay)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: relay.path)
        }

        func manifest(_ dir: String) -> URL {
            root.appendingPathComponent(
                "Library/Application Support/\(dir)/NativeMessagingHosts/me.somalabs.onepass.json")
        }

        func json(_ dir: String) throws -> [String: Any] {
            let data = try Data(contentsOf: manifest(dir))
            return try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        }

        func cleanUp() { try? FileManager.default.removeItem(at: root) }
    }

    func install(_ home: Home, ids: [String], installed: Set<String>) -> [URL] {
        NativeMessagingManifests.install(
            home: home.root, relay: home.relay, extensionIDs: ids, isInstalled: { installed.contains($0) })
    }

    @Test func writesOneManifestPerInstalledBrowserFamily() throws {
        let home = try Home(browsers: ["Google/Chrome", "BraveSoftware/Brave-Browser", "Mozilla"])
        defer { home.cleanUp() }
        let written = install(
            home, ids: [Self.chromeID, Self.firefoxID],
            installed: ["com.google.Chrome", "com.brave.Browser", "org.mozilla.firefox"])
        #expect(written.count == 3)

        let chrome = try home.json("Google/Chrome")
        #expect(chrome["name"] as? String == "me.somalabs.onepass")
        #expect(chrome["type"] as? String == "stdio")
        #expect(chrome["path"] as? String == home.relay.path)
        #expect(chrome["allowed_origins"] as? [String] == ["chrome-extension://\(Self.chromeID)/"])
        #expect(chrome["allowed_extensions"] == nil)
        #expect(try home.json("BraveSoftware/Brave-Browser")["allowed_origins"] as? [String]
            == ["chrome-extension://\(Self.chromeID)/"])

        let firefox = try home.json("Mozilla")
        #expect(firefox["allowed_extensions"] as? [String] == [Self.firefoxID])
        #expect(firefox["allowed_origins"] == nil)
    }

    @Test func browsersNotInstalledOrNeverLaunchedGetNothing() throws {
        // Edge is installed but never launched (no support folder); Chrome has a folder but the
        // app is gone.
        let home = try Home(browsers: ["Google/Chrome"])
        defer { home.cleanUp() }
        let written = install(home, ids: [Self.chromeID], installed: ["com.microsoft.edgemac"])
        #expect(written.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: home.manifest("Google/Chrome").path))
        #expect(!FileManager.default.fileExists(
            atPath: home.root.appendingPathComponent("Library/Application Support/Microsoft Edge").path))
    }

    @Test func aFamilyWithoutAServedIdGetsNoManifest() throws {
        // Only the Firefox id is configured (the Chrome Web Store id is not known yet).
        let home = try Home(browsers: ["Google/Chrome", "Mozilla"])
        defer { home.cleanUp() }
        let written = install(
            home, ids: [Self.firefoxID], installed: ["com.google.Chrome", "org.mozilla.firefox"])
        #expect(written == [home.manifest("Mozilla")])
    }

    @Test func identicalManifestsAreNotRewrittenAndStaleOnesAre() throws {
        let home = try Home(browsers: ["Google/Chrome"])
        defer { home.cleanUp() }
        let installed: Set<String> = ["com.google.Chrome"]
        #expect(install(home, ids: [Self.chromeID], installed: installed).count == 1)
        #expect(install(home, ids: [Self.chromeID], installed: installed).isEmpty)
        // A manifest that points elsewhere (an old copy of the app, another program) is replaced.
        try Data(#"{"name":"me.somalabs.onepass","path":"/tmp/other"}"#.utf8).write(to: home.manifest("Google/Chrome"))
        #expect(install(home, ids: [Self.chromeID], installed: installed).count == 1)
        #expect(try home.json("Google/Chrome")["path"] as? String == home.relay.path)
    }

    @Test func noRelayNoManifest() throws {
        let home = try Home(browsers: ["Google/Chrome"])
        defer { home.cleanUp() }
        try FileManager.default.removeItem(at: home.relay)
        #expect(install(home, ids: [Self.chromeID], installed: ["com.google.Chrome"]).isEmpty)
    }

    @Test func malformedIdsAreNeverWritten() throws {
        let home = try Home(browsers: ["Google/Chrome", "Mozilla"])
        defer { home.cleanUp() }
        _ = install(
            home, ids: [Self.chromeID, "bad id", "x\"y", Self.firefoxID],
            installed: ["com.google.Chrome", "org.mozilla.firefox"])
        #expect(try home.json("Google/Chrome")["allowed_origins"] as? [String]
            == ["chrome-extension://\(Self.chromeID)/"])
        #expect(try home.json("Mozilla")["allowed_extensions"] as? [String] == [Self.firefoxID])
    }
}
#endif
