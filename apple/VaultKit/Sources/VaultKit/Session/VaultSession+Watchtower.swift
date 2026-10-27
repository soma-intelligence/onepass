import Foundation
import OnePassCore

/// Watchtower (milestone 5, apps side): the core analyzes, VaultKit fetches the public data.
///
/// The core makes no network call. A report runs in two passes when breach lookups are on: the
/// first one, offline, returns the local findings and the SHA-1 prefixes it could not look up
/// (`missingPrefixes`); `WatchtowerFetcher` downloads those ranges from Have I Been Pwned, then the
/// second pass compares the suffixes on the device. Only 5 hex characters per distinct password
/// leave the device, with the `Add-Padding` header so that the response size says nothing either
/// (milestone 5 spec, section 3.3). The 2FA and passkey catalogs are downloaded whole, so they say
/// nothing about the vault's sites.
extension VaultSession {
    /// Defaults of the spec: an expiration is reported 30 days ahead, a password is old at a year.
    nonisolated public static let watchtowerExpiryWarningDays: UInt16 = 30
    nonisolated public static let watchtowerOldPasswordDays: UInt16 = 365

    /// One analysis of the visible vaults (hidden ones are left out). `ranges` nil turns breach
    /// lookups off; an empty array runs the offline pass that lists the prefixes to fetch.
    public func watchtowerReport(
        ranges: [FfiRangeResponse]?, twofaDirectory: Data?, passkeysDirectory: Data?
    ) async throws -> FfiWatchtowerReport {
        let options = FfiWatchtowerOptions(
            expiryWarningDays: Self.watchtowerExpiryWarningDays,
            oldPasswordDays: Self.watchtowerOldPasswordDays,
            ranges: ranges,
            twofaDirectory: twofaDirectory,
            passkeysDirectory: passkeysDirectory,
            excludedVaultIds: hiddenVaultIDs.sorted())
        return try await read { try $0.watchtowerReport(options: options) }
    }
}

/// Download of the public Watchtower data: HIBP password ranges (kept in memory, for one hour, and
/// dropped by `clear` on lock) and the 2fa.directory catalogs (kept on disk in Caches for a week).
/// Ephemeral `URLSession`: no cookie, no URL cache, no credential.
public actor WatchtowerFetcher {
    public static let rangeBase = "https://api.pwnedpasswords.com/range/"
    public static let twofaDirectoryURL = URL(string: "https://api.2fa.directory/v4/all.json")!
    public static let passkeysDirectoryURL = URL(string: "https://passkeys-api.2fa.directory/v1/all.json")!
    /// Largest range body the core reads (spec 3.3) and largest catalog (spec 3.4).
    public static let maxRangeBytes = 4 << 20
    public static let maxCatalogBytes = 16 << 20
    static let rangeLifetime: TimeInterval = 3600
    static let catalogLifetime: TimeInterval = 7 * 24 * 3600
    static let parallelRequests = 6

    private let session: URLSession
    private let cacheDirectory: URL?
    private var ranges: [String: (body: Data, at: Date)] = [:]
    /// Bumped by `clear()`: a download that started before a lock never lands in `ranges`.
    private var epoch = 0

    public init(session: URLSession? = nil, cacheDirectory: URL? = WatchtowerFetcher.defaultCacheDirectory) {
        self.session = session ?? Self.makeSession()
        self.cacheDirectory = cacheDirectory
    }

    public static var defaultCacheDirectory: URL? {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?
            .appending(path: "Watchtower", directoryHint: .isDirectory)
    }

    static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.urlCache = nil
        config.urlCredentialStorage = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 60
        config.httpAdditionalHeaders = ["User-Agent": "OnePass-Watchtower"]
        return URLSession(configuration: config)
    }

    /// Exactly 5 upper-case hex characters: nothing else can reach a URL.
    public nonisolated static func isValidPrefix(_ prefix: String) -> Bool {
        prefix.utf8.count == 5 && prefix.utf8.allSatisfy { (48...57).contains($0) || (65...70).contains($0) }
    }

    /// The range request of a prefix, with the padding header; nil for anything but a prefix.
    public nonisolated static func rangeRequest(prefix: String) -> URLRequest? {
        guard isValidPrefix(prefix), let url = URL(string: rangeBase + prefix) else { return nil }
        var request = URLRequest(url: url)
        request.setValue("true", forHTTPHeaderField: "Add-Padding")
        return request
    }

    /// The responses for `prefixes`, from memory when fresh, else downloaded (a few at a time).
    /// A prefix that fails is left out: the core then reports a partial lookup. `progress` gets
    /// (done, total) after each prefix.
    public func ranges(
        for prefixes: [String], progress: @escaping @Sendable (Int, Int) -> Void = { _, _ in }
    ) async -> [FfiRangeResponse] {
        let now = Date.now
        let started = epoch
        ranges = ranges.filter { now.timeIntervalSince($0.value.at) < Self.rangeLifetime }
        let wanted = Array(Set(prefixes.filter(Self.isValidPrefix))).sorted()
        var out: [FfiRangeResponse] = []
        var toFetch: [String] = []
        for prefix in wanted {
            if let held = ranges[prefix] {
                out.append(FfiRangeResponse(prefix: prefix, body: held.body))
            } else {
                toFetch.append(prefix)
            }
        }
        let total = wanted.count
        var done = out.count
        progress(done, total)
        let session = session
        await withTaskGroup(of: (String, Data?).self) { group in
            var next = toFetch.makeIterator()
            for _ in 0..<Self.parallelRequests {
                guard let prefix = next.next() else { break }
                group.addTask { (prefix, await Self.fetchRange(prefix, session: session)) }
            }
            while let (prefix, body) = await group.next() {
                if epoch != started || Task.isCancelled {
                    group.cancelAll()
                    break
                }
                if let body {
                    ranges[prefix] = (body, .now)
                    out.append(FfiRangeResponse(prefix: prefix, body: body))
                }
                done += 1
                progress(done, total)
                if let prefix = next.next() {
                    group.addTask { (prefix, await Self.fetchRange(prefix, session: session)) }
                }
            }
        }
        return out
    }

    private static func fetchRange(_ prefix: String, session: URLSession) async -> Data? {
        guard let request = rangeRequest(prefix: prefix) else { return nil }
        return await fetch(request, session: session, limit: maxRangeBytes)
    }

    /// Streams the body and gives up past `limit`, so a huge or endless body never sits in memory.
    private static func fetch(_ request: URLRequest, session: URLSession, limit: Int) async -> Data? {
        guard let (bytes, response) = try? await session.bytes(for: request),
            let http = response as? HTTPURLResponse, http.statusCode == 200,
            http.expectedContentLength <= Int64(limit)
        else { return nil }
        var data = Data()
        do {
            for try await byte in bytes {
                guard data.count < limit else { return nil }
                data.append(byte)
            }
        } catch {
            return nil
        }
        return data
    }

    /// The 2FA and passkey catalogs: the disk copy while under a week old, else a download (the
    /// stale copy serves when the download fails). Nil when neither exists.
    public func siteDirectories(allowNetwork: Bool) async -> (twofa: Data?, passkeys: Data?) {
        async let twofa = catalog(Self.twofaDirectoryURL, file: "2fa-directory.json", allowNetwork: allowNetwork)
        async let passkeys = catalog(Self.passkeysDirectoryURL, file: "passkeys-directory.json", allowNetwork: allowNetwork)
        return await (twofa, passkeys)
    }

    private func catalog(_ url: URL, file: String, allowNetwork: Bool) async -> Data? {
        let path = cacheDirectory?.appending(path: file)
        let cached = path.flatMap { try? Data(contentsOf: $0) }
        let age = path.flatMap { try? FileManager.default.attributesOfItem(atPath: $0.path)[.modificationDate] as? Date }
            .map { Date.now.timeIntervalSince($0) }
        if let cached, let age, age < Self.catalogLifetime { return cached }
        guard allowNetwork else { return cached }
        guard let fresh = await Self.fetch(URLRequest(url: url), session: session, limit: Self.maxCatalogBytes) else {
            return cached
        }
        if let path, let dir = cacheDirectory {
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try? fresh.write(to: path, options: .atomic)
        }
        return fresh
    }

    /// On lock: the ranges held say which prefixes the vault has.
    public func clear() {
        epoch += 1
        ranges.removeAll()
    }
}
