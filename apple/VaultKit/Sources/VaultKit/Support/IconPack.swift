import CryptoKit
import Foundation
import Synchronization

/// A pack of brand icons keyed by domain, built by `scripts/icon_pack.py` from open sets (Simple
/// Icons, gilbarbara/logos, 2FA Directory; licenses in `docs/icon-pack.md`).
///
/// Nothing here asks anyone for one site's icon: the app ships a baseline pack and may replace it
/// with a newer whole pack, the same bytes for everyone, accepted only when its manifest carries an
/// Ed25519 signature by the key the app trusts (`IconPackStore`).
///
/// Format 1 (big-endian): `OPIP`, a format byte (1), the index length (u32), the index (JSON:
/// `format`, `version`, `size`, `icons` as `[offset, length, flags]` into the bytes that follow,
/// `domains` as domain to icon number; optional `names`, a brand name squashed to lowercase letters
/// and digits to icon number, and `tenants`, domains whose icon is not inherited by their
/// subdomains; and `rejects`, the dHashes of hosting-platform icons as 16 lowercase hex digits), then
/// the icons (square lossless WebP, `size` pixels unless flagged 128). Flags are bits: 1 = a one
/// color mark (monochrome), 2 = this icon is 128 pixels, not `size`; both can be set (flags 3).
public struct IconPack: Sendable {
    public static let magic = Data("OPIP".utf8)
    public static let format: UInt8 = 1
    /// More than any pack the build makes (about 15 MB at 256 px): a larger file is refused unread.
    public static let maxBytes = 64 * 1024 * 1024
    static let maxIndexBytes = 8 * 1024 * 1024

    public struct Icon: Equatable, Sendable {
        /// Square WebP, `pixels` on a side.
        public let data: Data
        /// A one color mark (drawn in the text color, like a template image).
        public let monochrome: Bool
        /// The side in pixels: 128 for an icon flagged so (flag bit 2), else the pack's `size`.
        public let pixels: Int
    }

    public let version: Int
    public let pixels: Int
    let icons: [(offset: Int, length: Int, flags: Int)]
    let domains: [String: Int]
    let names: [String: Int]
    let tenants: Set<String>
    /// dHashes (`IconHash`) of hosting-platform icons: a gym member portal serving its club
    /// software's favicon, a shop on a site builder serving the builder's. A site icon within
    /// `rejectDistance` of one is never shown as the brand's logo. Empty for a pack without the key.
    public let rejects: [UInt64]
    /// The whole file (memory mapped when read from disk: never copied) and where the icons start.
    let data: Data
    let iconsStart: Int
    /// The search rows, built on the first search.
    private let searchIndex = SearchIndex()

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
        let names: [String: Int]?
        let tenants: [String]?
        let rejects: [String]?
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
        let iconsStart = start + 9 + length
        let blobCount = data.endIndex - iconsStart
        var icons: [(Int, Int, Int)] = []
        icons.reserveCapacity(index.icons.count)
        for entry in index.icons {
            guard entry.count == 3 else { throw .malformedIndex }
            let (offset, size, flags) = (entry[0], entry[1], entry[2])
            guard offset >= 0, size > 0, offset <= blobCount - size else { throw .outOfBounds }
            icons.append((offset, size, flags))
        }
        for number in Array(index.domains.values) + Array((index.names ?? [:]).values)
        where !(0..<icons.count).contains(number) {
            throw .outOfBounds
        }
        var rejects: [UInt64] = []
        for text in index.rejects ?? [] {
            guard text.utf8.count == 16, text.allSatisfy({ ("0"..."9").contains($0) || ("a"..."f").contains($0) }),
                let value = UInt64(text, radix: 16)
            else { throw .malformedIndex }
            rejects.append(value)
        }
        self.version = index.version
        self.pixels = index.size
        self.icons = icons.map { (offset: $0.0, length: $0.1, flags: $0.2) }
        self.domains = index.domains
        self.names = index.names ?? [:]
        self.tenants = Set(index.tenants ?? [])
        self.rejects = rejects
        self.data = data
        self.iconsStart = iconsStart
    }

    /// The icon of `host`: the host itself without `www.`, then each parent name down to two
    /// labels (`accounts.firefox.com`, then `firefox.com`), never a bare public suffix. A tenant
    /// domain (a platform that hosts other brands: `acme.zendesk.com` is Acme's help desk) gives its
    /// icon to itself only, never to its subdomains.
    public func icon(forHost host: String) -> Icon? {
        var name = host.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        if name.hasPrefix("www.") { name.removeFirst(4) }
        var labels = name.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard labels.count >= 2, labels.allSatisfy({ !$0.isEmpty }) else { return nil }
        let floor = SiteIconLoader.registrableDomain(of: name)?.split(separator: ".").count ?? 2
        var first = true
        while labels.count >= floor {
            let candidate = labels.joined(separator: ".")
            if let number = domains[candidate], first || !tenants.contains(candidate) { return icon(number) }
            labels.removeFirst()
            first = false
        }
        return nil
    }

    /// The icon of a brand named `title` ("Reddit", "Burger King"), for an item with no web
    /// address: the whole title, squashed like the pack's names (lowercase letters and digits,
    /// accents dropped, "&" read "and"), at least three characters. A title that is itself a web
    /// address ("reddit.com") is looked up as a host.
    public func icon(forTitle title: String) -> Icon? {
        let trimmed = title.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !trimmed.contains(" "), trimmed.contains("."), let host = ItemIconResolver.host(of: trimmed),
            let found = icon(forHost: host)
        {
            return found
        }
        let key = Self.squash(trimmed)
        guard key.count >= 3, let number = names[key] else { return nil }
        return icon(number)
    }

    /// Largest Hamming distance between two dHashes of the same icon (`REJECT_DISTANCE` in
    /// scripts/icon_pack.py).
    public static let rejectDistance = 6

    /// A dHash with fewer or more bits set says little about the icon (a flat tile hashes 0): it is
    /// never refused, and such a reject is ignored (`MIN_HASH_BITS` / `MAX_HASH_BITS` in the build).
    public static let minHashBits = 8
    public static let maxHashBits = 56

    static func isInformative(_ hash: UInt64) -> Bool {
        (minHashBits...maxHashBits).contains(hash.nonzeroBitCount)
    }

    /// Whether `png` is a hosting-platform icon: its dHash is within `rejectDistance` of one of
    /// `rejects`. An image that does not hash, or whose hash is not informative, is not refused.
    public static func isRejected(_ png: Data, by rejects: [UInt64]) -> Bool {
        guard !rejects.isEmpty, let hash = IconHash.dHash(png), isInformative(hash) else { return false }
        return rejects.contains { isInformative($0) && IconHash.distance($0, hash) <= rejectDistance }
    }

    /// `scripts/icon_pack.py squash`: letters and digits only, accents dropped.
    static func squash(_ text: String) -> String {
        let folded = text.lowercased().replacingOccurrences(of: "&", with: "and")
            .applyingTransform(.stripDiacritics, reverse: false) ?? text
        return String(folded.unicodeScalars.filter { ("a"..."z").contains($0) || ("0"..."9").contains($0) }.map(Character.init))
    }

    /// One searchable icon: its best name, its shortest domain, its number.
    public struct Entry: Hashable, Sendable {
        /// The squashed brand name (the domain itself for an icon that has no name).
        public let name: String
        public let domain: String?
        public let icon: Int
    }

    fileprivate struct Row: Sendable {
        let entry: Entry
        /// `name` squashed (the same as `name` for a named icon).
        let key: String
        let domains: [String]
    }

    fileprivate final class SearchIndex: Sendable {
        private let rows = Mutex<[Row]?>(nil)
        func get(_ pack: IconPack) -> [Row] {
            rows.withLock { state in
                if let state { return state }
                var byNumber: [Int: [String]] = [:]
                for (domain, number) in pack.domains { byNumber[number, default: []].append(domain) }
                for number in Array(byNumber.keys) {
                    byNumber[number]?.sort { ($0.count, $0) < ($1.count, $1) }
                }
                var built: [Row] = []
                var named = Set<Int>()
                for (name, number) in pack.names where !name.isEmpty {
                    let domains = byNumber[number] ?? []
                    built.append(Row(entry: Entry(name: name, domain: domains.first, icon: number), key: name, domains: domains))
                    named.insert(number)
                }
                for (number, domains) in byNumber where !named.contains(number) {
                    guard let first = domains.first else { continue }
                    built.append(Row(entry: Entry(name: first, domain: first, icon: number), key: IconPack.squash(first), domains: domains))
                }
                state = built
                return built
            }
        }
    }

    /// Icons whose brand name or domain matches `query` (squashed like the pack's names), best
    /// first: exact name, name prefix, domain prefix, name substring; ties by shorter name. One
    /// entry per icon.
    public func search(_ query: String, limit: Int = 60) -> [Entry] {
        let key = Self.squash(query)
        let raw = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !key.isEmpty, limit > 0 else { return [] }
        var best: [Int: (rank: Int, entry: Entry)] = [:]
        for row in searchIndex.get(self) {
            let rank: Int
            if row.key == key {
                rank = 0
            } else if row.key.hasPrefix(key) {
                rank = 1
            } else if row.domains.contains(where: { $0.hasPrefix(raw) }) {
                rank = 2
            } else if row.key.contains(key) {
                rank = 3
            } else {
                continue
            }
            if let current = best[row.entry.icon],
                (current.rank, current.entry.name.count, current.entry.name) <= (rank, row.entry.name.count, row.entry.name)
            {
                continue
            }
            best[row.entry.icon] = (rank, row.entry)
        }
        let sorted = best.values.sorted {
            ($0.rank, $0.entry.name.count, $0.entry.name) < ($1.rank, $1.entry.name.count, $1.entry.name)
        }
        return sorted.prefix(limit).map(\.entry)
    }

    /// The icon with this number in the pack, nil when out of range.
    public func icon(number: Int) -> Icon? {
        icons.indices.contains(number) ? icon(number) : nil
    }

    func icon(_ number: Int) -> Icon {
        let entry = icons[number]
        let start = iconsStart + entry.offset
        // A copy of the icon's bytes alone: a slice would keep its offsets into the whole pack.
        return Icon(data: Data(data[start..<(start + entry.length)]), monochrome: entry.flags & 1 != 0,
            pixels: entry.flags & 2 != 0 ? 128 : pixels)
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

    /// The Ed25519 public key (raw 32 bytes, base64) the published manifest must be signed with.
    ///
    /// Deliberately empty: the signing key is created once by the founder, never by a build or an
    /// agent (docs/icon-pack.md, "Clé de signature"). While it is empty `refreshIfDue` returns
    /// `.disabled` and makes no request at all: the app shows the pack it ships with, updated with
    /// each app release.
    public static let publicKey = ""

    private let baseline: URL?
    private let directory: URL
    private let key: Data?
    private let baseURL: URL
    private let session: URLSession
    private let now: @Sendable () -> Date
    /// The pack in use, read once (`pack()`), replaced by a refresh. Behind a lock rather than the
    /// actor: a row asks for its icon synchronously, on its first frame.
    private let current = Mutex<(loaded: IconPack?, didLoad: Bool)>((nil, false))

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

    /// The pack in use (newest of baseline and download), loaded once. Memory mapped: the icons are
    /// read from the file as they are asked for.
    public nonisolated func pack() -> IconPack? {
        current.withLock { state in
            if !state.didLoad {
                state.didLoad = true
                state.loaded = [baseline, downloaded].compactMap { $0 }.compactMap(Self.read).max { $0.version < $1.version }
            }
            return state.loaded
        }
    }

    public nonisolated func icon(forHost host: String) -> IconPack.Icon? {
        pack()?.icon(forHost: host)
    }

    public nonisolated func icon(forTitle title: String) -> IconPack.Icon? {
        pack()?.icon(forTitle: title)
    }

    private nonisolated var downloaded: URL { directory.appending(path: Self.packName) }

    private static func read(_ url: URL) -> IconPack? {
        (try? Data(contentsOf: url, options: .mappedIfSafe)).flatMap { try? IconPack(data: $0) }
    }

    /// Copies the baseline into `directory` when it is newer than the pack there, so a process that
    /// reads only that folder (the AutoFill extension, through the App Group) finds the pack the app
    /// ships with. Returns true when it wrote.
    @discardableResult
    public func shareBaseline() -> Bool {
        guard let baseline, let shipped = Self.read(baseline),
            shipped.version > (Self.read(downloaded)?.version ?? 0),
            let data = try? Data(contentsOf: baseline, options: .mappedIfSafe)
        else { return false }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return swapIn(data)
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
        guard swapIn(data) else { return .failed }
        current.withLock { $0 = (fresh, true) }
        return .updated(version: fresh.version)
    }

    /// Written beside its place, then renamed over it: a reader sees the old pack or the new one.
    private func swapIn(_ data: Data) -> Bool {
        let target = downloaded
        let temporary = directory.appending(path: ".\(Self.packName).\(UUID().uuidString)")
        do {
            try data.write(to: temporary, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            if FileManager.default.fileExists(atPath: target.path()) {
                _ = try FileManager.default.replaceItemAt(target, withItemAt: temporary)
            } else {
                try FileManager.default.moveItem(at: temporary, to: target)
            }
            return true
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            return false
        }
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
