import Compression
import Foundation
import OnePassCore

/// "Passkeys restées dans 1Password": a 1Password 1PUX export never carries a passkey's private
/// key, so the core imports such a login without it and only counts a `passkey_needs_cxf` warning.
/// The warning names no item, and the core hides the source tag that would identify one
/// (`FfiItemSummary.tags`). This file finds the items on the Apple side, with no core change:
///
/// 1. `scan` reads the export's `export.data` before the import bytes are wiped and lists the
///    entries whose passkey has no key, by the same rule as the core (`onepux.rs`, `item_draft`).
/// 2. `match` pairs each entry with the vault item the import wrote (title and site), first among
///    the items the import created or changed, then, alone, any one of the vault.
/// 3. `PasskeyMigrationStore` keeps the matched item ids on this device; an item leaves the list
///    once it holds a real passkey (`passkeyCount > 0`), so the list empties itself as the person
///    recreates them or brings them over by Credential Exchange.
///
/// Only titles, addresses and account names are read from the file; passwords and every other
/// value are never decoded.
public enum PasskeyMigration {
    /// The warning code of the core for a passkey imported without its private key.
    public static let warningCode = "passkey_needs_cxf"

    /// How many passkeys of a preview or import summary came without their key.
    public static func keylessCount(_ summary: FfiImportSummary) -> Int {
        summary.warnings.filter { $0.code == warningCode }.reduce(0) { $0 + Int($1.count) }
    }

    /// One 1PUX entry with at least one passkey the import cannot carry.
    public struct Entry: Equatable, Sendable {
        /// 1Password's vault and item uuids, `<vault>/<item>`: the core's source tag after
        /// `onepass:src:1pux:` (kept for a later core API that would expose it).
        public var source: String
        public var title: String
        /// The item's first address, as written in the export.
        public var url: String?
        /// The passkey's account name, when the export gives one.
        public var userName: String

        public init(source: String, title: String, url: String?, userName: String) {
            self.source = source
            self.title = title
            self.url = url
            self.userName = userName
        }
    }

    // MARK: - Scan

    /// The entries of a 1PUX export whose passkeys came without a private key, in export order.
    /// Empty for any other format, a damaged zip, or an `export.data` that does not decode: the
    /// import itself still reports the count, only the list stays empty.
    public static func scan(format: String, data: Data) -> [Entry] {
        guard format == "1pux", var json = ZipEntryReader.entry(named: "export.data", in: data) else { return [] }
        // The decompressed document holds every secret of the export: wiped before returning.
        defer { VaultSession.wipeImportBuffer(&json) }
        guard let root = try? JSONDecoder().decode(OnePux.Root.self, from: json) else { return [] }
        var out: [Entry] = []
        for vault in root.accounts.elements.flatMap(\.vaults.elements) {
            let vaultUUID = vault.attrs?.uuid?.value.trimmed ?? ""
            for item in vault.items.elements {
                // Trashed and deleted entries are skipped by the core: never imported.
                let state = item.state?.value.trimmed
                if state == "trashed" || state == "deleted" { continue }
                let passkeys = item.details?.passkeyObjects ?? []
                // The core keeps a passkey only on a login (category 001) and only with its key.
                let isLogin = item.categoryUuid?.value.trimmed == "001"
                guard passkeys.contains(where: { !$0.hasKey || !isLogin }) else { continue }
                let url = item.overview?.url?.value.trimmed.nonEmpty
                    ?? item.overview?.urls.elements.lazy.compactMap { $0.url?.value.trimmed.nonEmpty }.first
                out.append(Entry(
                    source: "\(vaultUUID)/\(item.uuid?.value.trimmed ?? "")",
                    title: item.overview?.title?.value.trimmed ?? "",
                    url: url,
                    userName: passkeys.lazy.map(\.userName).first { !$0.isEmpty } ?? ""))
            }
        }
        return out
    }

    // MARK: - Match

    /// What the matching needs of a vault item: `FfiItemSummary` or an invented one in tests.
    public struct Candidate: Equatable, Sendable {
        public var id: String
        public var title: String
        public var primaryURL: String?
        public var updatedAt: Int64

        public init(id: String, title: String, primaryURL: String?, updatedAt: Int64) {
            self.id = id
            self.title = title
            self.primaryURL = primaryURL
            self.updatedAt = updatedAt
        }

        public init(_ s: FfiItemSummary) {
            self.init(id: s.id, title: s.title, primaryURL: s.primaryUrl, updatedAt: s.updatedAt)
        }
    }

    /// Item id to `updatedAt` of the vault's items before the import: what `match` compares to.
    public static func snapshot(_ summaries: [FfiItemSummary], vaultID: String) -> [String: Int64] {
        Dictionary(
            summaries.filter { $0.vaultId == vaultID && $0.trashedAt == nil }.map { ($0.id, $0.updatedAt) },
            uniquingKeysWith: { a, _ in a })
    }

    /// The vault item each entry became, in entry order, each item at most once. An entry matches
    /// an item of the same title (when the entry has one) and the same site host (when the entry
    /// has an address). Items the import created or changed (absent from `before`, or with another
    /// `updatedAt`) are tried first; failing that, an entry takes the one item of the vault that
    /// matches it, never a guess among several.
    public static func match(_ entries: [Entry], before: [String: Int64], after: [Candidate]) -> [String] {
        let touched = after.filter { before[$0.id] != $0.updatedAt }
        var taken = Set<String>()
        var out: [String] = []
        for entry in entries {
            let fits = { (c: Candidate) in !taken.contains(c.id) && matches(entry, c) }
            let pick = touched.first(where: fits) ?? {
                let all = after.filter(fits)
                return all.count == 1 ? all[0] : nil
            }()
            guard let pick else { continue }
            taken.insert(pick.id)
            out.append(pick.id)
        }
        return out
    }

    static func matches(_ e: Entry, _ c: Candidate) -> Bool {
        let title = e.title.trimmed
        if !title.isEmpty, title.caseInsensitiveCompare(c.title.trimmed) != .orderedSame { return false }
        if let host = host(e.url) {
            guard host == self.host(c.primaryURL) else { return false }
        } else if title.isEmpty {
            // Neither a title nor an address: nothing to tell it from another item.
            return false
        }
        return true
    }

    /// Lower-cased host of an address written with or without its scheme, `www.` dropped.
    public static func host(_ raw: String?) -> String? {
        guard let raw = raw?.trimmed, !raw.isEmpty else { return nil }
        let withScheme = raw.contains("://") ? raw : "https://\(raw)"
        guard var host = URLComponents(string: withScheme)?.host?.lowercased(), !host.isEmpty else { return nil }
        if host.hasPrefix("www.") { host.removeFirst(4) }
        return host
    }

    /// The page "Ouvrir le site" opens: the item's own address when it is a web one (a 1Password
    /// login keeps the sign-in page), else the site's root. A per-site "security settings" path is
    /// not reliable across sites, so none is guessed.
    public static func siteURL(_ raw: String?) -> URL? {
        guard let raw = raw?.trimmed, !raw.isEmpty else { return nil }
        let withScheme = raw.contains("://") ? raw : "https://\(raw)"
        guard let url = URL(string: withScheme), let scheme = url.scheme?.lowercased(),
            scheme == "https" || scheme == "http", let host = url.host, !host.isEmpty
        else { return nil }
        return url
    }
}

// MARK: - Store

/// The items imported with a passkey to recreate, kept on this device per account (`UserDefaults`,
/// item ids only, never a title or an address). Local on purpose: marking the items in the vault
/// (a tag) would write and sync every one of them and show a working note among the person's own
/// tags; the list is a reminder of one import on one device and empties itself.
public struct PasskeyMigrationStore: @unchecked Sendable {
    public struct Ref: Hashable, Codable, Sendable {
        public var vaultID: String
        public var itemID: String

        public init(vaultID: String, itemID: String) {
            self.vaultID = vaultID
            self.itemID = itemID
        }
    }

    private let defaults: UserDefaults
    private let key: String

    /// `accountID`: the account the import went into (`VaultSettings.accountID`); a session with
    /// no account id yet (demo, first run) shares the "local" list.
    public init(defaults: UserDefaults = .standard, accountID: String?) {
        self.defaults = defaults
        let account = accountID?.trimmed.nonEmpty ?? "local"
        key = "onepass.passkeyMigration.\(account)"
    }

    public var refs: Set<Ref> {
        guard let data = defaults.data(forKey: key),
            let list = try? JSONDecoder().decode([Ref].self, from: data)
        else { return [] }
        return Set(list)
    }

    public func add(_ new: [Ref]) {
        save(refs.union(new))
    }

    public func remove(_ ref: Ref) {
        save(refs.subtracting([ref]))
    }

    /// The tracked items still waiting for a passkey, in title order: in the list, not trashed,
    /// with no passkey field. Items not in `summaries` (a hidden vault, another device's deletion)
    /// are left out here but kept, so a list read while the vault is still loading loses nothing.
    public func pending(in summaries: [FfiItemSummary]) -> [FfiItemSummary] {
        let refs = refs
        guard !refs.isEmpty else { return [] }
        return summaries
            .filter {
                refs.contains(Ref(vaultID: $0.vaultId, itemID: $0.id)) && $0.trashedAt == nil && $0.passkeyCount == 0
            }
            .sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
    }

    /// Drops the items that now hold a real passkey: they never come back to the list, even if the
    /// passkey is removed later. Returns how many were dropped.
    @discardableResult
    public func prune(_ summaries: [FfiItemSummary]) -> Int {
        let refs = refs
        guard !refs.isEmpty else { return 0 }
        let done = Set(summaries.filter { $0.passkeyCount > 0 }.map { Ref(vaultID: $0.vaultId, itemID: $0.id) })
        let kept = refs.subtracting(done)
        if kept.count != refs.count { save(kept) }
        return refs.count - kept.count
    }

    private func save(_ refs: Set<Ref>) {
        guard !refs.isEmpty else {
            defaults.removeObject(forKey: key)
            return
        }
        let sorted = refs.sorted { ($0.vaultID, $0.itemID) < ($1.vaultID, $1.itemID) }
        defaults.set(try? JSONEncoder().encode(sorted), forKey: key)
    }
}

// MARK: - 1PUX document (only what the scan needs)

/// The 1PUX `export.data` shapes the scan reads, as leniently as the core: a list element that
/// does not decode is dropped, a value of another JSON type reads as absent.
private enum OnePux {
    struct Root: Decodable {
        var accounts: Lenient<Account>
    }

    struct Account: Decodable {
        var vaults: Lenient<Vault>
    }

    struct Vault: Decodable {
        var attrs: Attrs?
        var items: Lenient<Item>

        enum CodingKeys: CodingKey { case attrs, items }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            attrs = try? c.decodeIfPresent(Attrs.self, forKey: .attrs)
            items = (try? c.decodeIfPresent(Lenient<Item>.self, forKey: .items)) ?? Lenient()
        }
    }

    struct Attrs: Decodable {
        var uuid: Text?
    }

    struct Item: Decodable {
        var uuid: Text?
        var state: Text?
        var categoryUuid: Text?
        var overview: Overview?
        var details: Details?

        enum CodingKeys: CodingKey { case uuid, state, categoryUuid, overview, details }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            uuid = try? c.decodeIfPresent(Text.self, forKey: .uuid)
            state = try? c.decodeIfPresent(Text.self, forKey: .state)
            categoryUuid = try? c.decodeIfPresent(Text.self, forKey: .categoryUuid)
            overview = try? c.decodeIfPresent(Overview.self, forKey: .overview)
            details = try? c.decodeIfPresent(Details.self, forKey: .details)
        }
    }

    struct Overview: Decodable {
        var title: Text?
        var url: Text?
        var urls: Lenient<OverviewURL>

        enum CodingKeys: CodingKey { case title, url, urls }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            title = try? c.decodeIfPresent(Text.self, forKey: .title)
            url = try? c.decodeIfPresent(Text.self, forKey: .url)
            urls = (try? c.decodeIfPresent(Lenient<OverviewURL>.self, forKey: .urls)) ?? Lenient()
        }
    }

    struct OverviewURL: Decodable {
        var url: Text?
    }

    /// `details.passkey`, `details.passkeys`, and section field values under a `passkey` key: the
    /// places the core looks (`passkey_objects`). Passwords and login fields are not declared, so
    /// never decoded.
    struct Details: Decodable {
        var passkeyObjects: [PasskeyProbe]

        enum CodingKeys: CodingKey { case passkey, passkeys, sections }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            var found = (try? c.decodeIfPresent(Probes.self, forKey: .passkey))?.list ?? []
            found += (try? c.decodeIfPresent(Probes.self, forKey: .passkeys))?.list ?? []
            let sections = (try? c.decodeIfPresent(Lenient<Section>.self, forKey: .sections)) ?? Lenient()
            for field in sections.elements.flatMap(\.fields.elements) {
                found += field.passkeys
            }
            passkeyObjects = found
        }
    }

    struct Section: Decodable {
        var fields: Lenient<Field>

        enum CodingKeys: CodingKey { case fields }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            fields = (try? c.decodeIfPresent(Lenient<Field>.self, forKey: .fields)) ?? Lenient()
        }
    }

    /// A section field: only an object `value` with a `passkey` member (any case) is read.
    struct Field: Decodable {
        var passkeys: [PasskeyProbe] = []

        enum CodingKeys: CodingKey { case value }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            guard let value = try? c.nestedContainer(keyedBy: AnyKey.self, forKey: .value) else { return }
            for key in value.allKeys where key.stringValue.caseInsensitiveCompare("passkey") == .orderedSame {
                passkeys += (try? value.decode(Probes.self, forKey: key))?.list ?? []
            }
        }
    }

    /// One passkey object or a list of them; anything else is none.
    struct Probes: Decodable {
        var list: [PasskeyProbe] = []

        init(from decoder: Decoder) throws {
            if let one = try? PasskeyProbe(from: decoder) {
                list = [one]
            } else if let many = try? decoder.singleValueContainer().decode(Lenient<PasskeyProbe>.self) {
                list = many.elements
            }
        }
    }

    /// Whether a passkey object has a credential id and a private key (the core's `full_passkey`
    /// spellings), and its account name. The key itself is never kept: only its presence.
    struct PasskeyProbe: Decodable {
        var hasKey: Bool
        var userName: String

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: AnyKey.self)
            func present(_ names: [String]) -> Bool {
                names.contains { name in
                    guard let key = AnyKey(stringValue: name),
                        let text = try? c.decodeIfPresent(String.self, forKey: key)
                    else { return false }
                    return !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                }
            }
            hasKey = present(["credentialId", "credentialID", "id"]) && present(["privateKey", "key"])
            userName = ["userName", "username"].lazy.compactMap { name in
                AnyKey(stringValue: name).flatMap { try? c.decodeIfPresent(String.self, forKey: $0) }?.trimmed.nonEmpty
            }.first ?? ""
        }
    }

    /// A text value the core reads leniently: a string, or a number written as text.
    struct Text: Decodable {
        var value: String

        init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if let s = try? c.decode(String.self) {
                value = s
            } else if let n = try? c.decode(Int64.self) {
                value = String(n)
            } else {
                throw DecodingError.dataCorruptedError(in: c, debugDescription: "not text")
            }
        }
    }

    /// A JSON list whose elements that do not decode are dropped (the core's `Lenient`). A value
    /// that is not a list reads as empty.
    struct Lenient<T: Decodable>: Decodable {
        var elements: [T] = []

        init() {}

        init(from decoder: Decoder) throws {
            guard var c = try? decoder.unkeyedContainer() else { return }
            while !c.isAtEnd {
                if let e = try? c.decode(T.self) {
                    elements.append(e)
                } else {
                    // Steps over the element that did not decode.
                    _ = try? c.decode(Skip.self)
                }
            }
        }
    }

    struct Skip: Decodable {
        init(from decoder: Decoder) throws {}
    }

    struct AnyKey: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }
}

// MARK: - Zip

/// Reads one entry of a zip (stored or deflated), as the core's bounded reader does: at most
/// 64 MiB decompressed, no ZIP64, the name compared as written and never used as a path. Nil on
/// anything unexpected.
enum ZipEntryReader {
    static let maxEntry = 64 << 20

    static func entry(named name: String, in zip: Data) -> Data? {
        // Read in place: no copy of the export (it holds every secret) is made here.
        zip.withUnsafeBytes { (b: UnsafeRawBufferPointer) -> Data? in
            guard let eocd = endOfCentralDirectory(b) else { return nil }
            let count = Int(u16(b, eocd + 10))
            var p = Int(u32(b, eocd + 16))
            for _ in 0..<count {
                guard p + 46 <= b.count, u32(b, p) == 0x0201_4B50 else { return nil }
                let method = u16(b, p + 10)
                let compressed = Int(u32(b, p + 20))
                let size = Int(u32(b, p + 24))
                let nameLength = Int(u16(b, p + 28))
                let extra = Int(u16(b, p + 30))
                let comment = Int(u16(b, p + 32))
                let local = Int(u32(b, p + 42))
                guard p + 46 + nameLength <= b.count else { return nil }
                let entryName = String(decoding: b[(p + 46)..<(p + 46 + nameLength)], as: UTF8.self)
                p += 46 + nameLength + extra + comment
                guard entryName == name else { continue }
                guard size <= maxEntry, local + 30 <= b.count, u32(b, local) == 0x0403_4B50 else { return nil }
                let start = local + 30 + Int(u16(b, local + 26)) + Int(u16(b, local + 28))
                guard start + compressed <= b.count else { return nil }
                let source = UnsafeRawBufferPointer(rebasing: b[start..<(start + compressed)])
                switch method {
                case 0: return compressed == size ? Data(source) : nil
                case 8: return inflate(source, size: size)
                default: return nil
                }
            }
            return nil
        }
    }

    private static func inflate(_ source: UnsafeRawBufferPointer, size: Int) -> Data? {
        guard size > 0 else { return Data() }
        guard let src = source.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
        var out = Data(count: size)
        let written = out.withUnsafeMutableBytes { dst in
            // COMPRESSION_ZLIB is raw DEFLATE (RFC 1951), the stream of zip method 8.
            compression_decode_buffer(
                dst.bindMemory(to: UInt8.self).baseAddress!, size, src, source.count, nil, COMPRESSION_ZLIB)
        }
        guard written == size else {
            VaultSession.wipeImportBuffer(&out)
            return nil
        }
        return out
    }

    /// The end-of-central-directory record, searched back over its largest comment (64 KiB).
    private static func endOfCentralDirectory(_ b: UnsafeRawBufferPointer) -> Int? {
        guard b.count >= 22 else { return nil }
        let lowest = max(0, b.count - 22 - 0xFFFF)
        var i = b.count - 22
        while i >= lowest {
            if u32(b, i) == 0x0605_4B50 { return i }
            i -= 1
        }
        return nil
    }

    private static func u16(_ b: UnsafeRawBufferPointer, _ i: Int) -> UInt16 {
        guard i >= 0, i + 2 <= b.count else { return 0 }
        return UInt16(b[i]) | UInt16(b[i + 1]) << 8
    }

    private static func u32(_ b: UnsafeRawBufferPointer, _ i: Int) -> UInt32 {
        guard i >= 0, i + 4 <= b.count else { return 0 }
        return UInt32(b[i]) | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2]) << 16 | UInt32(b[i + 3]) << 24
    }
}

private extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
    var nonEmpty: String? { isEmpty ? nil : self }
}
