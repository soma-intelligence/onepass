import CryptoKit
import Foundation
import OnePassCore

/// The site pack in use, and its periodic refresh (docs/site-pack.md).
///
/// The site pack says which sites offer two-factor authentication or passkeys and where their
/// security settings are. Watchtower reads it whole, on the device: no request ever names a site.
/// The pack in use is the newer of the baseline (shipped in the app, trusted as part of it) and the
/// last downloaded one, which is used only when `verifySitePack` accepts its stored manifest,
/// signature and bytes under the compiled key, at every load. A refresh, at most once a week,
/// downloads the signed manifest from the project's releases; when its version is newer, it
/// downloads the whole pack, has the core check it (signature, size, SHA-256, recipes) and swaps the
/// three files in. No key, no refresh and no downloaded pack: the baseline stays.
public actor SitePackStore {
    /// Where the weekly workflow publishes (a prerelease never marked Latest: the Mac updater reads
    /// `releases/latest`).
    public static let defaultBaseURL = URL(string: "https://github.com/soma-intelligence/onepass/releases/download/site-pack/")!
    /// File name of the pack shipped in the app's resources.
    public static let bundledName = "onepass-sites"
    static let manifestName = "site-pack-manifest.json"
    static let signatureName = "site-pack-manifest.json.sig"
    static let packName = "onepass-sites.json"
    static let checkedName = "checked"
    public static let refreshInterval: TimeInterval = 7 * 24 * 3600
    static let maxManifestBytes = 64 * 1024
    static let maxSignatureBytes = 1024
    static let maxPackBytes = 16 * 1024 * 1024

    /// The Ed25519 public key (raw 32 bytes, base64) the published manifest must be signed with.
    ///
    /// Deliberately empty: the signing key is created once by the founder, never by a build or an
    /// agent (docs/site-pack.md, "Clé de signature"). While it is empty `refreshIfDue` returns
    /// `.disabled` and makes no request at all: Watchtower uses the pack the app ships with.
    public static let publicKey = ""

    private let baseline: URL?
    private let directory: URL
    private let key: Data?
    private let baseURL: URL
    private let session: URLSession
    private let now: @Sendable () -> Date
    /// The pack in use and its version, read once (`pack()`), replaced by a refresh.
    private var loaded: (data: Data, version: UInt64)?
    private var didLoad = false

    public init(
        baseline: URL?, directory: URL, publicKey: String = SitePackStore.publicKey,
        baseURL: URL = SitePackStore.defaultBaseURL, session: URLSession = SitePackStore.session,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.baseline = baseline
        self.directory = directory
        self.key = Data(base64Encoded: publicKey).flatMap { $0.count == 32 ? $0 : nil }
        self.baseURL = baseURL
        self.session = session
        self.now = now
    }

    /// The bytes of the pack in use (newer of baseline and verified download), nil when there is
    /// none: Watchtower then runs no site check.
    public func pack() -> Data? {
        current()?.data
    }

    private func current() -> (data: Data, version: UInt64)? {
        if !didLoad {
            didLoad = true
            loaded = [shipped(), downloaded()].compactMap { $0 }.max { $0.version < $1.version }
        }
        return loaded
    }

    private func shipped() -> (data: Data, version: UInt64)? {
        guard let baseline, let data = try? Data(contentsOf: baseline, options: .mappedIfSafe),
            let version = try? sitePackVersion(pack: data)
        else { return nil }
        return (data, version)
    }

    /// The stored trio, only when it verifies again under the compiled key.
    private func downloaded() -> (data: Data, version: UInt64)? {
        guard let key,
            let manifest = try? Data(contentsOf: directory.appending(path: Self.manifestName)),
            let signature = try? Data(contentsOf: directory.appending(path: Self.signatureName)),
            let data = try? Data(contentsOf: directory.appending(path: Self.packName), options: .mappedIfSafe),
            let version = try? verifySitePack(manifest: manifest, signature: signature, pack: data, publicKey: key)
        else { return nil }
        return (data, version)
    }

    public enum RefreshResult: Equatable, Sendable {
        case disabled
        case notDue
        case upToDate
        case updated(version: UInt64)
        case failed
    }

    /// Checks for a newer pack when the last check is a week old (or `force`).
    @discardableResult
    public func refreshIfDue(force: Bool = false) async -> RefreshResult {
        guard let key else { return .disabled }
        let marker = directory.appending(path: Self.checkedName)
        if !force, let checked = try? FileManager.default.attributesOfItem(atPath: marker.path())[.modificationDate] as? Date,
            now().timeIntervalSince(checked) < Self.refreshInterval
        {
            return .notDue
        }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        guard
            let manifestData = try? await PackDownload.get(
                baseURL.appending(path: Self.manifestName), limit: Self.maxManifestBytes, session: session),
            let signature = try? await PackDownload.get(
                baseURL.appending(path: Self.signatureName), limit: Self.maxSignatureBytes, session: session),
            let manifest = SitePackManifest.verified(manifestData, signature: signature, publicKey: key)
        else { return .failed }
        touch(marker)
        guard manifest.version > current()?.version ?? 0 else { return .upToDate }
        guard
            let data = try? await PackDownload.get(
                baseURL.appending(path: manifest.pack.file), limit: manifest.pack.size, session: session),
            let version = try? verifySitePack(manifest: manifestData, signature: signature, pack: data, publicKey: key),
            version > current()?.version ?? 0
        else { return .failed }
        // The pack first, the manifest last: a reader that finds a mixed trio fails to verify it and
        // falls back to the baseline.
        do {
            try PackDownload.swapIn(data, as: Self.packName, in: directory)
            try PackDownload.swapIn(signature, as: Self.signatureName, in: directory)
            try PackDownload.swapIn(manifestData, as: Self.manifestName, in: directory)
        } catch {
            return .failed
        }
        loaded = (data, version)
        didLoad = true
        return .updated(version: version)
    }

    private func touch(_ url: URL) {
        if FileManager.default.fileExists(atPath: url.path()) {
            try? FileManager.default.setAttributes([.modificationDate: now()], ofItemAtPath: url.path())
        } else {
            FileManager.default.createFile(atPath: url.path(), contents: Data(), attributes: [.modificationDate: now()])
        }
    }

    /// No cookies, no cache, and time for a pack of a few megabytes on a slow line.
    public static let session: URLSession = {
        let configuration = URLSession.ephemeralNoCookiesConfiguration
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 600
        return URLSession(configuration: configuration)
    }()
}

extension SitePackStore {
    /// The store of the app: the pack shipped in `bundle`, downloads in `container.sitePackFolder`.
    public static func live(container: SharedContainer = .resolve(), bundle: Bundle = .main) -> SitePackStore {
        SitePackStore(
            baseline: bundle.url(forResource: bundledName, withExtension: "json"), directory: container.sitePackFolder)
    }
}

extension SharedContainer {
    /// Where the downloaded site pack lives: the App Group's caches, this process's caches without
    /// a shared container.
    public var sitePackFolder: URL {
        let caches =
            isShared
            ? root.appendingPathComponent("Library/Caches", isDirectory: true)
            : FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        return caches.appendingPathComponent("OnePass/SitePack", isDirectory: true)
    }
}

/// What a refresh reads from the manifest before it downloads the pack: its signature is checked
/// here first, so a forged manifest never costs a download. The core checks everything again
/// (`verifySitePack`) once the pack is there.
struct SitePackManifest: Decodable {
    struct File: Decodable {
        let file: String
        let size: Int
    }

    let format: Int
    let version: UInt64
    let pack: File

    static func verified(_ data: Data, signature: Data, publicKey: Data) -> SitePackManifest? {
        guard let text = String(data: signature, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
            let raw = Data(base64Encoded: text), raw.count == 64,
            let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey),
            key.isValidSignature(raw, for: data),
            let manifest = try? JSONDecoder().decode(SitePackManifest.self, from: data),
            manifest.format == 1,
            // A plain file name, so the download URL stays inside the release.
            manifest.pack.file.range(of: #"^onepass-sites-[0-9]{1,12}\.json$"#, options: .regularExpression) != nil,
            manifest.pack.size > 0, manifest.pack.size <= SitePackStore.maxPackBytes
        else { return nil }
        return manifest
    }
}
