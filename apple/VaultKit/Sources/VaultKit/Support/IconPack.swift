import CryptoKit
import Foundation

/// A pack of brand icons keyed by domain, built by `scripts/icon_pack.py` from open sets (Simple
/// Icons, gilbarbara/logos, 2FA Directory; licenses in `docs/icon-pack.md`).
///
/// Nothing here asks anyone for one site's icon: the app ships a baseline pack and may replace it
/// with a newer whole pack, the same bytes for everyone, accepted only when its manifest carries an
/// Ed25519 signature by the key the app trusts (`IconPackStore`).
///
/// Format 1 (big-endian): `OPIP`, a format byte (1), the index length (u32), the index (JSON:
/// `format`, `version`, `size`, `icons` as `[offset, length, flags]` into the bytes that follow,
/// `domains` as domain to icon number), then the icons (square lossless WebP, `size` pixels).
public struct IconPack: Sendable {
    public static let magic = Data("OPIP".utf8)
    public static let format: UInt8 = 1
    /// More than any pack the build makes (about 15 MB at 256 px): a larger file is refused unread.
    public static let maxBytes = 64 * 1024 * 1024
    static let maxIndexBytes = 8 * 1024 * 1024

    public struct Icon: Equatable, Sendable {
        /// Square WebP, `IconPack.pixels` on a side.
        public let data: Data
        /// A one color mark (drawn in the text color, like a template image).
        public let monochrome: Bool
    }

    public let version: Int
    public let pixels: Int
    let icons: [(offset: Int, length: Int, flags: Int)]
    let domains: [String: Int]
    let blob: Data

    public var domainCount: Int { domains.count }
    public var iconCount: Int { icons.count }

    public enum Problem: Error, Equatable, Sendable {
        case tooLarge
        case notAPack
        case malformedIndex
        case outOfBounds
    }

    private struct Index: Decodable {
        let format: Int
        let version: Int
        let size: Int
        let icons: [[Int]]
        let domains: [String: Int]
    }

    /// Parses a pack, every offset and every domain's icon number checked.
    public init(data: Data) throws(Problem) {
        guard data.count <= Self.maxBytes else { throw .tooLarge }
        let bytes = [UInt8](data.prefix(9))
        guard bytes.count == 9, Data(bytes[0..<4]) == Self.magic, bytes[4] == Self.format else { throw .notAPack }
        let length = Int(bytes[5]) << 24 | Int(bytes[6]) << 16 | Int(bytes[7]) << 8 | Int(bytes[8])
        guard length <= Self.maxIndexBytes, 9 + length <= data.count else { throw .outOfBounds }
        let start = data.startIndex
        guard let index = try? JSONDecoder().decode(Index.self, from: data[(start + 9)..<(start + 9 + length)]),
            index.format == Int(Self.format), index.size > 0, index.version > 0
        else { throw .malformedIndex }
        let blob = Data(data[(start + 9 + length)...])
        var icons: [(Int, Int, Int)] = []
        icons.reserveCapacity(index.icons.count)
        for entry in index.icons {
            guard entry.count == 3 else { throw .malformedIndex }
            let (offset, size, flags) = (entry[0], entry[1], entry[2])
            guard offset >= 0, size > 0, offset <= blob.count - size else { throw .outOfBounds }
            icons.append((offset, size, flags))
        }
        for number in index.domains.values where !(0..<icons.count).contains(number) {
            throw .outOfBounds
        }
        self.version = index.version
        self.pixels = index.size
        self.icons = icons.map { (offset: $0.0, length: $0.1, flags: $0.2) }
        self.domains = index.domains
        self.blob = blob
    }

    /// The icon of `host`: the host itself without `www.`, then each parent name down to two
    /// labels (`accounts.firefox.com`, then `firefox.com`), never a bare public suffix.
    public func icon(forHost host: String) -> Icon? {
        var name = host.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        if name.hasPrefix("www.") { name.removeFirst(4) }
        var labels = name.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard labels.count >= 2, labels.allSatisfy({ !$0.isEmpty }) else { return nil }
        let floor = SiteIconLoader.registrableDomain(of: name)?.split(separator: ".").count ?? 2
        while labels.count >= floor {
            if let number = domains[labels.joined(separator: ".")] { return icon(number) }
            labels.removeFirst()
        }
        return nil
    }

    func icon(_ number: Int) -> Icon {
        let entry = icons[number]
        let start = blob.startIndex + entry.offset
        return Icon(data: blob[start..<(start + entry.length)], monochrome: entry.flags & 1 != 0)
    }
}

/// The manifest published next to a pack, signed (`<manifest>.sig`, base64 Ed25519 over the exact
/// manifest bytes).
public struct IconPackManifest: Decodable, Equatable, Sendable {
    public struct File: Decodable, Equatable, Sendable {
        public let file: String
        public let size: Int
        public let sha256: String
    }

    public let format: Int
    public let version: Int
    public let pack: File

    static let maxBytes = 64 * 1024

    public enum Problem: Error, Equatable, Sendable {
        case badSignature
        case malformed
        case unsupportedFormat
    }

    /// The manifest, only when `signature` (base64) verifies under `publicKey` (raw 32 bytes).
    public static func verified(_ data: Data, signature: Data, publicKey: Data) throws(Problem) -> IconPackManifest {
        guard data.count <= maxBytes,
            let text = String(data: signature, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
            let raw = Data(base64Encoded: text), raw.count == 64,
            let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey),
            key.isValidSignature(raw, for: data)
        else { throw .badSignature }
        guard let manifest = try? JSONDecoder().decode(IconPackManifest.self, from: data) else { throw .malformed }
        guard manifest.format == Int(IconPack.format) else { throw .unsupportedFormat }
        // A plain file name, so the download URL stays inside the release.
        guard manifest.pack.file.range(of: #"^onepass-icons-[0-9]{1,12}\.bin$"#, options: .regularExpression) != nil,
            manifest.pack.size > 0, manifest.pack.size <= IconPack.maxBytes,
            manifest.pack.sha256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
        else { throw .malformed }
        return manifest
    }
}

/// The pack in use, and its periodic refresh.
///
/// The pack in use is the newest valid one of the baseline (shipped in the app, trusted as part of
/// it) and the last downloaded one. A refresh, at most once a week, downloads the signed manifest
/// from the project's releases; when its version is newer, it downloads the whole pack, checks its
/// size and SHA-256 against the manifest, parses it, and swaps it in atomically. No key, no
/// refresh: the baseline stays.
public actor IconPackStore {
    /// Where the weekly workflow publishes (a release that is never marked Latest: the updater
    /// reads `releases/latest`).
    public static let defaultBaseURL = URL(string: "https://github.com/soma-intelligence/onepass/releases/download/icon-pack/")!
    static let manifestName = "icon-pack-manifest.json"
    static let packName = "onepass-icons.bin"
    static let checkedName = "checked"
    public static let refreshInterval: TimeInterval = 7 * 24 * 3600

    /// The Ed25519 public key the published manifest must be signed with. Empty until the founder
    /// creates the key (docs/icon-pack.md): the app then keeps its baseline.
    public static let publicKey = ""

    private let baseline: URL?
    private let directory: URL
    private let key: Data?
    private let baseURL: URL
    private let session: URLSession
    private let now: @Sendable () -> Date
    private var loaded: IconPack?
    private var didLoad = false

    public init(
        baseline: URL?, directory: URL, publicKey: String = IconPackStore.publicKey,
        baseURL: URL = IconPackStore.defaultBaseURL, session: URLSession = IconPackStore.session,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.baseline = baseline
        self.directory = directory
        self.key = Data(base64Encoded: publicKey).flatMap { $0.count == 32 ? $0 : nil }
        self.baseURL = baseURL
        self.session = session
        self.now = now
    }

    /// The pack in use (newest of baseline and download), loaded once.
    public func pack() -> IconPack? {
        if !didLoad {
            didLoad = true
            loaded = [baseline, directory.appending(path: Self.packName)]
                .compactMap { $0 }
                .compactMap { url in (try? Data(contentsOf: url, options: .mappedIfSafe)).flatMap { try? IconPack(data: $0) } }
                .max { $0.version < $1.version }
        }
        return loaded
    }

    public func icon(forHost host: String) -> IconPack.Icon? {
        pack()?.icon(forHost: host)
    }

    public enum RefreshResult: Equatable, Sendable {
        case disabled
        case notDue
        case upToDate
        case updated(version: Int)
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
        guard let manifestData = await get(baseURL.appending(path: Self.manifestName), limit: IconPackManifest.maxBytes),
            let signature = await get(baseURL.appending(path: Self.manifestName + ".sig"), limit: 1024),
            let manifest = try? IconPackManifest.verified(manifestData, signature: signature, publicKey: key)
        else { return .failed }
        touch(marker)
        guard manifest.version > (pack()?.version ?? 0) else { return .upToDate }
        guard let data = await get(baseURL.appending(path: manifest.pack.file), limit: manifest.pack.size),
            data.count == manifest.pack.size,
            SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == manifest.pack.sha256,
            let fresh = try? IconPack(data: data), fresh.version == manifest.version
        else { return .failed }
        // Written beside its place, then renamed over it: a reader sees the old pack or the new one.
        let target = directory.appending(path: Self.packName)
        let temporary = directory.appending(path: ".\(Self.packName).\(UUID().uuidString)")
        do {
            try data.write(to: temporary, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            if FileManager.default.fileExists(atPath: target.path()) {
                _ = try FileManager.default.replaceItemAt(target, withItemAt: temporary)
            } else {
                try FileManager.default.moveItem(at: temporary, to: target)
            }
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            return .failed
        }
        loaded = fresh
        didLoad = true
        return .updated(version: fresh.version)
    }

    private func touch(_ url: URL) {
        if FileManager.default.fileExists(atPath: url.path()) {
            try? FileManager.default.setAttributes([.modificationDate: now()], ofItemAtPath: url.path())
        } else {
            FileManager.default.createFile(atPath: url.path(), contents: Data(), attributes: [.modificationDate: now()])
        }
    }

    /// HTTPS GET, 200 only, at most `limit` bytes (the declared length is checked first, the
    /// downloaded file after).
    private func get(_ url: URL, limit: Int) async -> Data? {
        guard url.scheme == "https",
            let (file, response) = try? await session.download(from: url),
            let http = response as? HTTPURLResponse, http.statusCode == 200,
            http.expectedContentLength <= Int64(limit)
        else { return nil }
        defer { try? FileManager.default.removeItem(at: file) }
        guard let size = (try? FileManager.default.attributesOfItem(atPath: file.path())[.size]) as? Int, size <= limit
        else { return nil }
        return try? Data(contentsOf: file)
    }

    /// No cookies, no cache, and time for a pack of a few megabytes on a slow line.
    public static let session: URLSession = {
        let configuration = URLSession.ephemeralNoCookiesConfiguration
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 600
        return URLSession(configuration: configuration)
    }()
}
