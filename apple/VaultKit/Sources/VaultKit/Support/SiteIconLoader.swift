import CoreGraphics
import CryptoKit
import Foundation
import ImageIO
import Synchronization
import UniformTypeIdentifiers

#if os(macOS)
import AppKit
#endif

extension URLSession {
    /// A fresh configuration with no cookies, no credential or URL cache and a 10 s timeout.
    /// Tests copy it to add a `URLProtocol` stub.
    public static var ephemeralNoCookiesConfiguration: URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 10
        configuration.waitsForConnectivity = false
        return configuration
    }

    /// Session for third party sites: ephemeral, never stores or sends cookies.
    public static let ephemeralNoCookies = URLSession(configuration: ephemeralNoCookiesConfiguration)
}

/// Loads site icons straight from the item's own site. HTTPS only, public host
/// names only (never an IP literal, `localhost`, a single-label name or a local network suffix such as
/// `.local`, `.lan`, `.home.arpa` or `.internal`: no LAN probing), and the name must resolve to public
/// addresses only (checked before any request: no private, loopback, link-local, CGNAT, unique-local
/// or multicast address). 256 KiB at most per response, no cookies, image type checked by ImageIO,
/// declared size checked before any decode, cached by host hash, failures remembered for a week.
///
/// Where the icon comes from, best first: the home page's `<link>` icons (`apple-touch-icon`,
/// `apple-touch-icon-precomposed`, `icon`, `shortcut icon`) and the icons of its web app manifest
/// (on the site, or on the host the page names for them, such as a brand's CDN: `a0.muscache.com` for
/// Airbnb, `s.pinimg.com` for Pinterest, with the same checks), ranked by the size they declare (SVG first, then the largest `sizes`); then
/// `/apple-touch-icon.png` and `/apple-touch-icon-precomposed.png`; then the monochrome `mask-icon`;
/// `/favicon.ico` last. A source of `goodPixels` or more ends the search; a smaller one is kept and the
/// next candidates are tried (at most `maxImageAttempts` images), the largest found wins. In an ICO
/// (or any file holding several images) the largest image is used.
///
/// SVG is never handed to ImageIO (it does not read it): on macOS it is drawn by `NSImage` at
/// `iconPixels` (`UIImage(data:)` does not read SVG, so other platforms skip it), and only when it has no
/// DOCTYPE or entity, no script, no embedded image or foreign object, and no reference other than a
/// `#fragment` inside the file itself (so drawing it fetches nothing).
///
/// The result is a square PNG of `iconPixels` (aspect kept, transparent padding, high quality
/// interpolation), or smaller for a small source: never more than twice the source's size.
///
/// A hosting platform's icon (`rejects`, from the icon pack: a gym portal serving its club software's
/// favicon) is never kept: the normalized PNG about to be kept is hashed (`IconHash`), and one within
/// `IconPack.rejectDistance` of a reject is refused and the next candidate tried. Every candidate
/// refused: the host has no icon (a failure, remembered like any other).
///
/// When the item's own host yields nothing (`dashboard.stripe.com`, `notion.so`), its registrable
/// domain (`stripe.com`, never a bare public suffix: `registrableDomain`) is tried, then `www.` plus
/// that domain, then the app hosts of that same domain (`app.`, `account.`, `my.`: a brand whose
/// home page refuses every client but a browser, such as `withings.com`, usually serves its icons
/// from its web app), each with every check above (public name, public addresses, HTTPS, caps). The
/// icon found is cached under the item's host too.
///
/// A source page whose icons are dead links (a stale manifest) does not use up the search: each kind
/// of candidate gets `maxFailuresPerKind` failed fetches at most before the next kind is tried.
///
/// Logos change: an icon older than `refreshAge` is still shown at once, and fetched again in the
/// background; the new one replaces it only when one was found. A redirect is followed only on the same host, or once
/// to another host of the same registrable domain (`notion.so` to `www.notion.so`) whose addresses
/// are public. The home page alone may instead make that one hop to the same name under another
/// suffix (`www.notion.so` to `www.notion.com`, `exemple.fr` to `exemple.com`). The rest of that
/// search then runs on the host it landed on.
///
/// The parent brand (`ParentBrand`): when the icon pack is given (`pack`), the same home page (and
/// the manifest, when it was fetched for its icons) also says which brand the site belongs to, with no
/// request of its own. Its name (`siteNames`) looked up in the pack's names gives `byName` ("Bay Club
/// Connect" is Bay Club); the domains it links to (`linkedDomains`) looked up in the pack's domains
/// give `byLink`. The pack icon numbers found are cached per host beside the icon, with the pack
/// version they belong to, and searched again on the same schedule as the icon, or at once when the
/// pack version changes.
///
/// Known limit: the system resolves the name again when it connects. A DNS server that answers a
/// public address to the check and a private one a moment later (DNS rebinding) still gets one
/// request to the private address; it learns nothing back (HTTPS to the same host name, no cookies).
public actor SiteIconLoader {
    static let maxBytes = 256 * 1024
    /// Largest declared width or height decoded: a small file can declare a huge bitmap.
    static let maxSourcePixels = 4096
    static let failureLifetime: TimeInterval = 7 * 24 * 3600
    /// Side of the stored PNG.
    static let iconPixels = 256
    /// A source this large ends the search (a 180 px touch icon: sharp on a 3x screen at 60 pt).
    static let goodPixels = 180
    /// Below this a source is a last resort.
    static let tinyPixels = 48
    /// Images fetched per host at most (on top of the home page and the manifest).
    static let maxImageAttempts = 8
    /// Failed fetches of one kind of candidate (manifest entries, page links...) before it is skipped.
    static let maxFailuresPerKind = 3
    /// Age after which a cached icon is fetched again in the background (still shown meanwhile).
    static let refreshAge: TimeInterval = 30 * 24 * 3600
    /// App hosts of a site's own domain, asked last (`app.withings.com` when `withings.com` refuses).
    static let appHostLabels = ["app", "account", "my"]
    /// Version in the cache file names: bumping it refetches every icon once.
    static let cacheVersion = "v4"

    private let cacheDirectory: URL
    private let session: URLSession
    private let resolver: any HostResolver
    private let enabled: @Sendable () -> Bool
    /// The icon pack's `rejects` (read at each search: a refreshed pack may bring new ones).
    private let rejects: @Sendable () -> [UInt64]
    /// The icon pack in use, for the parent brand; nil: no parent brand is looked for.
    private let pack: @Sendable () -> IconPack?
    private var inFlight: [String: Task<Data?, Never>] = [:]
    /// Hosts waiting for a parent brand re-search (a new pack), first in first out, and the number
    /// of such searches running: at most `prefetchWidth` at once, so a new pack never sends every
    /// cached host at once.
    private var brandQueue: [String] = []
    private var brandRunning = 0
    /// Callers waiting for a queued or running parent brand search, by host: each resumed once,
    /// when that search ends (a cancelled caller too: it is never left hanging nor resumed twice).
    private var brandWaiters: [String: [CheckedContinuation<Data?, Never>]] = [:]
    /// Most parent brand re-searches seen running at once (tests).
    private(set) var brandRunningPeak = 0
    /// Icons already read or fetched, by host: a row shows its icon on its first frame, never the
    /// placeholder first.
    private let memory = Mutex<[String: Data]>([:])
    /// Parent brands already read, by host (nil: no record on disk).
    private let brands = Mutex<[String: ParentBrand?]>([:])

    public init(
        cacheDirectory: URL, session: URLSession = .ephemeralNoCookies,
        resolver: any HostResolver = SystemHostResolver(),
        enabled: @escaping @Sendable () -> Bool,
        rejects: @escaping @Sendable () -> [UInt64] = { [] },
        pack: @escaping @Sendable () -> IconPack? = { nil }
    ) {
        self.cacheDirectory = cacheDirectory
        self.session = session
        self.resolver = resolver
        self.enabled = enabled
        self.rejects = rejects
        self.pack = pack
    }

    /// PNG bytes of the site's icon, or nil (disabled, not HTTPS, no icon, recently failed).
    public func icon(for url: String) async -> Data? {
        guard enabled(), let host = Self.fetchableHost(of: url) else { return nil }
        if let cached = cachedIcon(host: host) {
            // A parent brand of an older pack (or none yet): searched again, a few hosts at a
            // time, and awaited, so the caller reads the new parent brand in the same task.
            if let age = iconAge(host: host), age <= Self.refreshAge, brandOutdated(host: host) {
                return await awaitBrandSearch(host: host) ?? cached
            }
            refreshIfStale(host: host)
            return cached
        }
        // A failure is not asked again before its time, unless the parent brand found with it
        // belongs to an older pack (or was never looked for): then searched again the same way.
        if let age = markerAge(host: host), age < Self.failureLifetime {
            guard brandOutdated(host: host) else { return nil }
            return await awaitBrandSearch(host: host)
        }

        if let task = inFlight[host] { return await task.value }
        let task = Task { await self.fetchAndStore(host: host) }
        inFlight[host] = task
        let result = await task.value
        inFlight[host] = nil
        if let result { memory.withLock { $0[host] = result } }
        return result
    }

    /// The icon already on this device (memory, else the disk cache), without waiting and without
    /// any request: what a row shows on its first frame.
    public nonisolated func cachedIcon(for url: String) -> Data? {
        guard enabled(), let host = Self.fetchableHost(of: url) else { return nil }
        return cachedIcon(host: host)
    }

    /// Loads the icons of `urls` in the background, a few hosts at a time (after an unlock), so
    /// lists opened later find them cached.
    public func prefetch(_ urls: [String]) async {
        guard enabled() else { return }
        var seen = Set<String>()
        let hosts = urls.compactMap(Self.fetchableHost(of:)).filter { seen.insert($0).inserted }
        let pending = hosts.filter { cachedIcon(host: $0) == nil }
        await withTaskGroup(of: Void.self) { group in
            var next = pending.makeIterator()
            for _ in 0..<Self.prefetchWidth {
                guard let host = next.next() else { break }
                group.addTask { _ = await self.icon(for: "https://" + host) }
            }
            while await group.next() != nil {
                if Task.isCancelled { group.cancelAll(); return }
                guard let host = next.next() else { continue }
                group.addTask { _ = await self.icon(for: "https://" + host) }
            }
        }
    }

    /// An icon cached more than `refreshAge` ago is fetched again, once, in the background. Found:
    /// it replaces the old one. Not found (or offline): the old one stays, asked again after
    /// another `refreshAge`.
    private func refreshIfStale(host: String) {
        guard inFlight[host] == nil, let age = iconAge(host: host) else { return }
        guard age > Self.refreshAge else {
            if brandOutdated(host: host) { queueBrandSearch(host: host) }
            return
        }
        let task = Task { await self.fetchAndStore(host: host, refreshing: true) }
        inFlight[host] = task
        Task {
            let fresh = await task.value
            self.finishRefresh(host: host, fresh: fresh)
        }
    }

    /// The icon after a parent brand search of `host`: joins the search under way for that host,
    /// else waits in the queue (`queueBrandSearch`).
    private func awaitBrandSearch(host: String) async -> Data? {
        if let task = inFlight[host] { return await task.value ?? cachedIcon(host: host) }
        return await withCheckedContinuation { continuation in
            brandWaiters[host, default: []].append(continuation)
            queueBrandSearch(host: host)
        }
    }

    /// Resumes every caller waiting on `host`, once.
    private func resumeBrandWaiters(host: String, icon: Data?) {
        guard let waiters = brandWaiters.removeValue(forKey: host) else { return }
        for waiter in waiters { waiter.resume(returning: icon) }
    }

    /// Queues a background search of `host` for its parent brand (once per host).
    private func queueBrandSearch(host: String) {
        guard inFlight[host] == nil, !brandQueue.contains(host) else { return }
        brandQueue.append(host)
        startBrandSearches()
    }

    private func startBrandSearches() {
        while brandRunning < Self.prefetchWidth, !brandQueue.isEmpty {
            let host = brandQueue.removeFirst()
            if let other = inFlight[host] {
                // Another search of this host started meanwhile: its waiters get its result.
                Task {
                    let icon = await other.value
                    self.resumeBrandWaiters(host: host, icon: icon ?? self.cachedIcon(host: host))
                }
                continue
            }
            brandRunning += 1
            brandRunningPeak = max(brandRunningPeak, brandRunning)
            let task = Task { await self.fetchAndStore(host: host, refreshing: true) }
            inFlight[host] = task
            Task {
                let fresh = await task.value
                self.finishBrandSearch(host: host, fresh: fresh)
            }
        }
    }

    private func finishBrandSearch(host: String, fresh: Data?) {
        inFlight[host] = nil
        if let fresh { memory.withLock { $0[host] = fresh } }
        brandRunning -= 1
        resumeBrandWaiters(host: host, icon: fresh ?? cachedIcon(host: host))
        startBrandSearches()
    }

    private func finishRefresh(host: String, fresh: Data?) {
        inFlight[host] = nil
        if let fresh {
            memory.withLock { $0[host] = fresh }
        } else {
            // Kept: dated now so the next try waits another `refreshAge`.
            try? FileManager.default.setAttributes(
                [.modificationDate: Date()], ofItemAtPath: cacheFile(host: host, ext: "png").path)
        }
    }

    /// Drops the icon cached for the host of `url` (memory and disk): the next `icon(for:)` searches
    /// the site again. Used when a cached icon turns out to be a hosting platform's.
    public func forget(_ url: String) {
        guard let host = Self.fetchableHost(of: url) else { return }
        memory.withLock { $0[host] = nil }
        try? FileManager.default.removeItem(at: cacheFile(host: host, ext: "png"))
    }

    /// Waits for the background refreshes under way (tests).
    func settle() async {
        while let task = inFlight.values.first {
            _ = await task.value
            await Task.yield()
        }
    }

    private func iconAge(host: String) -> TimeInterval? {
        let path = cacheFile(host: host, ext: "png").path
        guard let date = (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
        else { return nil }
        return Date().timeIntervalSince(date)
    }

    /// Hosts fetched at once by `prefetch`.
    static let prefetchWidth = 4

    private nonisolated func cachedIcon(host: String) -> Data? {
        if let hit = memory.withLock({ $0[host] }) { return hit }
        guard let disk = try? Data(contentsOf: cacheFile(host: host, ext: "png")), isImage(disk) else { return nil }
        memory.withLock { $0[host] = disk }
        return disk
    }

    /// The lowercased host of an HTTPS URL this loader may fetch, else nil.
    nonisolated static func fetchableHost(of url: String) -> String? {
        guard let components = URLComponents(string: url.trimmingCharacters(in: .whitespacesAndNewlines)),
            components.scheme?.lowercased() == "https",
            let host = components.host?.lowercased(), !host.isEmpty, isFetchableHost(host)
        else { return nil }
        return host
    }

    /// Suffixes of local network names (Bonjour, home routers, RFC 8375 `home.arpa`, ICANN `internal`,
    /// common corporate and router defaults): never fetched.
    static let localSuffixes = [
        "localhost", "local", "lan", "home.arpa", "internal", "localdomain", "home", "intranet", "corp",
        "private",
    ]

    /// A public DNS name: not an IP literal (v4, in any of the shorthand forms resolvers accept, or
    /// v6), not `localhost`, not a local network suffix (`localSuffixes`), not a single label (a LAN
    /// device name).
    static func isFetchableHost(_ host: String) -> Bool {
        var name = host.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty, !name.contains(":"), !name.hasPrefix("[") else { return false }
        if localSuffixes.contains(where: { name == $0 || name.hasSuffix("." + $0) }) { return false }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, labels.allSatisfy({ !$0.isEmpty }), let last = labels.last else { return false }
        // No top-level domain is numeric: `10.0.0.1`, `127.1`, `0x7f.1` or `192.168.1.0x1` are addresses.
        if last.allSatisfy(\.isNumber) { return false }
        if last.hasPrefix("0x"), last.dropFirst(2).allSatisfy(\.isHexDigit) { return false }
        return true
    }

    // MARK: Fetching

    private enum Fetched {
        case data(Data, URL)
        case miss
        case offline
    }

    /// The hosts asked, in order: the item's own, its registrable domain, `www.` plus that domain,
    /// then its app hosts (`appHostLabels`), each once, never a bare public suffix.
    static func siteHosts(for host: String) -> [String] {
        var name = host.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        var hosts = [name]
        if let domain = registrableDomain(of: name) {
            let candidates = [domain, "www." + domain] + appHostLabels.map { $0 + "." + domain }
            for candidate in candidates where !hosts.contains(candidate) {
                hosts.append(candidate)
            }
        }
        return hosts.filter(isFetchableHost)
    }

    /// Searches the item's host, then its parent domain (`siteHosts`); the icon found is stored
    /// under the item's host. A failure is remembered only when every host was really asked.
    private func fetchAndStore(host: String, refreshing: Bool = false) async -> Data? {
        let hosts = Self.siteHosts(for: host)
        let current = pack()
        /// The parent brand of the first page read (or of a parent host's cache).
        var brand: ParentBrand?
        /// Recorded for the item's host whatever the icon search gives, unless offline with nothing.
        func record(offline: Bool = false) {
            guard let current else { return }
            if let brand {
                storeBrand(brand, host: host)
            } else if !offline {
                storeBrand(ParentBrand(packVersion: current.version, byName: nil, byLink: nil), host: host)
            }
        }
        for (index, site) in hosts.enumerated() {
            switch await attempt(site, remember: index > 0, refreshing: refreshing, pack: current, brand: &brand) {
            case .icon(let png):
                if site != host { store(png, host: host) }
                record()
                return png
            case .miss:
                continue
            case .offline:
                // Says nothing about the site: not remembered, the next display asks again.
                record(offline: true)
                return nil
            case .refused:
                // The item's own name points at a private address: no parent is asked.
                if index == 0 {
                    if !refreshing { markFailure(host: host) }
                    record()
                    return nil
                }
            }
        }
        // A refresh that found nothing keeps the icon in hand (no marker over it).
        if !refreshing { markFailure(host: host) }
        record()
        return nil
    }

    private enum Attempt {
        case icon(Data)
        case miss
        case offline
        /// Resolves to a non public address (or to nothing).
        case refused
    }

    /// One host searched. `remember`: its own cache and failure marker are used and written (a
    /// parent domain other items share); the item's host is written by the caller. `refreshing`: the
    /// parent's cache is not taken as the answer (it is as old as the icon being refreshed).
    ///
    /// `pack` given: the parent brand of the first home page read is set in `brand` (a parent host
    /// whose cached icon is used gives its cached parent brand).
    private func attempt(
        _ host: String, remember: Bool, refreshing: Bool = false, pack: IconPack? = nil,
        brand: inout ParentBrand?
    ) async -> Attempt {
        let rejects = self.rejects()
        if remember, !refreshing {
            if let cached = try? Data(contentsOf: cacheFile(host: host, ext: "png")), isImage(cached),
                !IconPack.isRejected(cached, by: rejects)
            {
                if brand?.isEmpty ?? true, let pack, let known = cachedBrand(host: host), known.packVersion == pack.version {
                    brand = known
                }
                return .icon(cached)
            }
            if let age = markerAge(host: host), age < Self.failureLifetime { return .miss }
        }
        // Before any request: every address the name resolves to must be public.
        guard let addresses = await resolver.addresses(for: host) else { return .offline }
        guard !addresses.isEmpty, addresses.allSatisfy(\.isPublic) else {
            if remember { markFailure(host: host) }
            return .refused
        }
        var offline = false
        // The host the search runs on: the home page may move it once within the same site.
        var site = host

        // The home page (truncated at the cap) and its manifest name the best icons.
        var candidates: [IconCandidate] = []
        if let home = URL(string: "https://\(host)/"), let page = await get(home, host: host, truncate: true, home: true, offline: &offline) {
            if let landed = page.url.host?.lowercased(), landed != host { site = landed }
            let base = page.url
            let links = Self.pageLinks(in: page.data, base: base, host: site)
            candidates += links.icons
            var manifestData: Data?
            if let manifest = links.manifest, let json = await get(manifest, host: site, truncate: false, offline: &offline) {
                candidates += Self.manifestIcons(in: json.data, base: json.url, host: site)
                manifestData = json.data
            }
            // The parent brand, from what was just read: no request of its own.
            if let pack, brand?.isEmpty ?? true {
                let found = Self.parentBrand(page: page.data, manifest: manifestData, host: site, pack: pack)
                brand = found
                if remember { storeBrand(found, host: host) }
            }
        }
        candidates += Self.wellKnownCandidates(host: site)

        var best: DecodedIcon?
        var attempts = 0
        /// Failed fetches per kind: a stale manifest's dead entries never use up the search.
        var failures: [IconCandidate.Kind: Int] = [:]
        /// Other hosts the page names for its icons, and whether they resolve to public addresses only.
        var publicHosts: [String: Bool] = [:]
        for candidate in Self.ranked(candidates) {
            if let best, best.sourcePixels >= Self.goodPixels { break }
            guard attempts < Self.maxImageAttempts else { break }
            // A size the site declares that cannot beat what is already in hand is not fetched.
            if let best, !candidate.vector, let declared = candidate.declared, declared <= best.sourcePixels {
                continue
            }
            if failures[candidate.kind, default: 0] >= Self.maxFailuresPerKind { continue }
            // An icon the page names on another host (its CDN): that host passes the same checks.
            let iconHost = candidate.url.host?.lowercased() ?? site
            if iconHost != site {
                guard Self.isFetchableHost(iconHost) else { continue }
                if publicHosts[iconHost] == nil {
                    guard let found = await resolver.addresses(for: iconHost) else {
                        offline = true
                        continue
                    }
                    publicHosts[iconHost] = !found.isEmpty && found.allSatisfy(\.isPublic)
                }
                guard publicHosts[iconHost] == true else { continue }
            }
            attempts += 1
            guard let fetched = await get(candidate.url, host: iconHost, truncate: false, offline: &offline),
                let decoded = Self.decodeIcon(fetched.data)
            else {
                failures[candidate.kind, default: 0] += 1
                continue
            }
            // A hosting platform's icon, not the brand's: the next candidate. Hashed on the
            // normalized PNG (at most `iconPixels` square), never on the download.
            if IconPack.isRejected(decoded.png, by: rejects) { continue }
            if decoded.sourcePixels > best?.sourcePixels ?? 0 { best = decoded }
        }

        if let best {
            store(best.png, host: host)
            return .icon(best.png)
        }
        if offline { return .offline }
        if remember { markFailure(host: host) }
        return .miss
    }

    /// The body of `fetch` and the URL it came from, nil on a miss; `offline` is set when the
    /// network is down.
    private func get(
        _ url: URL, host: String, truncate: Bool, home: Bool = false, offline: inout Bool
    ) async -> (data: Data, url: URL)? {
        switch await fetch(url, host: host, truncate: truncate, home: home) {
        case .data(let data, let final): return (data, final)
        case .miss: return nil
        case .offline:
            offline = true
            return nil
        }
    }

    /// GET with a hard size cap. Misses on non 2xx, a redirect off HTTPS or off the site (see
    /// `RedirectGuard`; `home`: the home page, which may also hop to its brand under another
    /// suffix), or (unless truncating, for the HTML page) a body over the cap.
    private func fetch(_ url: URL, host: String, truncate: Bool, home: Bool) async -> Fetched {
        var request = URLRequest(url: url)
        request.httpShouldHandleCookies = false
        do {
            let guardian = RedirectGuard(host: host, resolver: resolver, home: home)
            let (bytes, response) = try await session.bytes(for: request, delegate: guardian)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
                let final = http.url, final.scheme?.lowercased() == "https",
                let landed = final.host?.lowercased(), landed == host || guardian.allowed(landed)
            else { return .miss }
            if !truncate, http.expectedContentLength > Int64(Self.maxBytes) { return .miss }
            var data = Data()
            for try await byte in bytes {
                if data.count >= Self.maxBytes {
                    if truncate { break }
                    return .miss
                }
                data.append(byte)
            }
            return .data(data, final)
        } catch let error as URLError where [.notConnectedToInternet, .networkConnectionLost, .cancelled].contains(error.code) {
            return .offline
        } catch {
            return .miss
        }
    }

    // MARK: Registrable domain

    /// Public suffixes of more than one label that names are commonly registered under, and hosting
    /// suffixes whose subdomains belong to different people (a `*.github.io` site is not GitHub).
    /// A short list on purpose: Foundation has no public suffix API. Anything else is registered
    /// directly under its top level domain.
    static let multiLabelSuffixes: Set<String> = [
        // United Kingdom, Ireland.
        "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "ac.uk", "gov.uk", "nhs.uk", "police.uk",
        // France, Belgium, Switzerland, Monaco.
        "gouv.fr", "asso.fr", "com.fr", "nom.fr", "tm.fr", "prd.fr",
        // Rest of Europe.
        "co.at", "or.at", "gv.at", "ac.at", "com.es", "org.es", "nom.es", "gob.es", "com.pt", "gov.pt",
        "com.pl", "net.pl", "org.pl", "gov.pl", "com.gr", "gov.gr", "co.hu", "com.ro", "com.ua", "gov.ua",
        "com.tr", "gov.tr", "org.tr", "co.il", "org.il", "gov.il", "ac.il",
        // Asia Pacific.
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "co.nz", "net.nz", "org.nz", "govt.nz",
        "ac.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "gr.jp", "ad.jp", "co.kr", "or.kr", "go.kr",
        "ac.kr", "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "org.hk", "gov.hk", "com.tw",
        "org.tw", "gov.tw", "com.sg", "gov.sg", "edu.sg", "com.my", "gov.my", "co.in", "net.in", "org.in",
        "gov.in", "ac.in", "firm.in", "co.id", "or.id", "go.id", "ac.id", "co.th", "in.th", "go.th",
        "ac.th", "com.ph", "gov.ph", "com.vn", "gov.vn", "com.pk", "gov.pk", "com.bd",
        // Americas.
        "com.br", "net.br", "org.br", "gov.br", "edu.br", "com.mx", "gob.mx", "org.mx", "com.ar", "gob.ar",
        "com.co", "gov.co", "com.pe", "gob.pe", "com.ec", "com.ve", "com.uy", "cl.cl", "gob.cl",
        // Africa, Middle East.
        "co.za", "org.za", "gov.za", "ac.za", "com.eg", "gov.eg", "com.sa", "gov.sa", "com.ng", "gov.ng",
        "co.ke", "or.ke", "co.ma", "gov.ma", "com.tn", "ac.ma",
        // Hosting suffixes.
        "github.io", "gitlab.io", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "web.app",
        "firebaseapp.com", "appspot.com", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
        "blogspot.com", "s3.amazonaws.com", "onrender.com", "fly.dev", "ngrok.io", "ngrok-free.app",
    ]

    /// The name registered for `host`: its public suffix (the longest match in
    /// `multiLabelSuffixes`, else its top level label) plus one label. Nil for a bare suffix
    /// (`com`, `co.uk`) or a malformed name.
    static func registrableDomain(of host: String) -> String? {
        var name = host.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard labels.count >= 2, labels.allSatisfy({ !$0.isEmpty }) else { return nil }
        var suffixLength = 1
        for length in stride(from: labels.count, through: 2, by: -1)
        where multiLabelSuffixes.contains(labels.suffix(length).joined(separator: ".")) {
            suffixLength = length
            break
        }
        guard labels.count > suffixLength else { return nil }
        return labels.suffix(suffixLength + 1).joined(separator: ".")
    }

    /// Two hosts whose registrable domains differ only by their suffix: the same label before it
    /// (`notion.so` and `www.notion.com`, `exemple.fr` and `exemple.com`).
    static func sameNameOtherSuffix(_ a: String, _ b: String) -> Bool {
        guard let left = registrableDomain(of: a), let right = registrableDomain(of: b), left != right,
            let leftName = left.split(separator: ".").first, let rightName = right.split(separator: ".").first
        else { return false }
        return leftName == rightName
    }

    /// Two hosts of the same registrable domain.
    static func sameSite(_ a: String, _ b: String) -> Bool {
        guard let left = registrableDomain(of: a) else { return false }
        return left == registrableDomain(of: b)
    }

    // MARK: Candidates

    /// One place an icon may be, with what the site says about it.
    struct IconCandidate: Equatable, Sendable {
        enum Kind: Sendable {
            /// `<link rel="apple-touch-icon">` or `apple-touch-icon-precomposed`.
            case touch
            /// `<link rel="icon">` or `shortcut icon`.
            case icon
            /// An entry of the web app manifest's `icons`.
            case manifest
            /// `/apple-touch-icon.png` or `/apple-touch-icon-precomposed.png`, asked without a link.
            case wellKnown
            /// `<link rel="mask-icon">`: a one colour SVG, better than nothing.
            case mask
            /// `/favicon.ico`, asked without a link.
            case favicon
        }

        let url: URL
        let kind: Kind
        /// Largest side named in `sizes`, nil when absent or unreadable.
        let declared: Int?
        /// An SVG, by its type or its extension.
        let vector: Bool

        /// Searched in this order first: what the page names, then the usual paths.
        var tier: Int {
            switch kind {
            case .touch, .icon, .manifest: 0
            case .wellKnown: 1
            case .mask: 2
            case .favicon: 3
            }
        }

        /// Expected size, for ranking within a tier. A vector draws sharp at any size; a touch icon
        /// without `sizes` is 180 px by convention; anything else unknown ranks last.
        var estimate: Int {
            if vector { return Int.max }
            if let declared { return declared }
            return kind == .touch ? 180 : 0
        }
    }

    /// The usual paths, asked even when the page names nothing.
    static func wellKnownCandidates(host: String) -> [IconCandidate] {
        [
            ("/apple-touch-icon.png", IconCandidate.Kind.wellKnown),
            ("/apple-touch-icon-precomposed.png", .wellKnown),
            ("/favicon.ico", .favicon),
        ].compactMap { path, kind in
            URL(string: "https://\(host)\(path)").map { IconCandidate(url: $0, kind: kind, declared: nil, vector: false) }
        }
    }

    /// Best first: by tier, then by expected size (largest first), page order breaking ties. SVG is
    /// dropped where it cannot be drawn; a URL named twice keeps its best place.
    static func ranked(_ candidates: [IconCandidate]) -> [IconCandidate] {
        let usable = candidates.enumerated().filter { !$0.element.vector || rendersSVG }
        let sorted = usable.sorted { a, b in
            if a.element.tier != b.element.tier { return a.element.tier < b.element.tier }
            if a.element.estimate != b.element.estimate { return a.element.estimate > b.element.estimate }
            return a.offset < b.offset
        }
        var seen = Set<URL>()
        return sorted.map(\.element).filter { seen.insert($0.url).inserted }
    }

    /// Largest side named in a `sizes` value (`"16x16 32x32"`), nil for none or `any`.
    static func largestSize(in sizes: String?) -> Int? {
        guard let sizes else { return nil }
        let sides = sizes.lowercased().split(whereSeparator: \.isWhitespace).compactMap { token -> Int? in
            let parts = token.split(separator: "x")
            guard parts.count == 2, let w = Int(parts[0]), let h = Int(parts[1]), w > 0, h > 0 else { return nil }
            return max(w, h)
        }
        return sides.max()
    }

    private static func isSVG(type: String?, url: URL) -> Bool {
        type?.lowercased().contains("svg") == true || url.pathExtension.lowercased() == "svg"
    }

    /// Resolves an icon reference against `base`: HTTPS on a public host name (the site itself or
    /// the one it names for its icons), nil otherwise. The addresses are checked before the fetch.
    private static func iconURL(_ reference: String, base: URL) -> URL? {
        guard let url = URL(string: reference.trimmingCharacters(in: .whitespacesAndNewlines), relativeTo: base)?
            .absoluteURL,
            url.scheme?.lowercased() == "https", let host = url.host, isFetchableHost(host)
        else { return nil }
        return url
    }

    // MARK: HTML

    /// Icons named by `<link>` tags (at most 16, HTTPS on a public host name) and the web app manifest
    /// (same host).
    static func pageLinks(in data: Data, base: URL, host: String) -> (icons: [IconCandidate], manifest: URL?) {
        let html = String(decoding: data, as: UTF8.self)
        guard let tag = try? NSRegularExpression(pattern: "<link\\b[^>]{0,4096}>", options: [.caseInsensitive])
        else { return ([], nil) }
        var icons: [IconCandidate] = []
        var manifest: URL?
        for match in tag.matches(in: html, range: NSRange(html.startIndex..., in: html)) {
            guard let r = Range(match.range, in: html) else { continue }
            let element = String(html[r])
            guard let relValue = attribute("rel", in: element), let link = attribute("href", in: element),
                let url = iconURL(link, base: base)
            else { continue }
            let rels = Set(relValue.lowercased().split(whereSeparator: \.isWhitespace).map(String.init))
            let kind: IconCandidate.Kind
            if rels.contains("apple-touch-icon") || rels.contains("apple-touch-icon-precomposed") {
                kind = .touch
            } else if rels.contains("icon") {
                kind = .icon
            } else if rels.contains("mask-icon") {
                kind = .mask
            } else {
                if rels.contains("manifest"), manifest == nil, url.host?.lowercased() == host { manifest = url }
                continue
            }
            guard icons.count < 16 else { continue }
            let vector = kind == .mask || isSVG(type: attribute("type", in: element), url: url)
            icons.append(IconCandidate(
                url: url, kind: kind, declared: largestSize(in: attribute("sizes", in: element)), vector: vector))
        }
        return (icons, manifest)
    }

    /// The value of one attribute of a tag, quoted or not.
    static func attribute(_ name: String, in element: String) -> String? {
        guard let regex = try? NSRegularExpression(
            pattern: "\\s\(name)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'>]+))", options: [.caseInsensitive])
        else { return nil }
        let range = NSRange(element.startIndex..., in: element)
        guard let match = regex.firstMatch(in: element, range: range) else { return nil }
        for n in 1...3 {
            if let r = Range(match.range(at: n), in: element) { return String(element[r]) }
        }
        return nil
    }

    /// The `icons` of a web app manifest (at most 16), HTTPS on a public host name. Monochrome icons are
    /// left out: they are silhouettes.
    static func manifestIcons(in data: Data, base: URL, host: String) -> [IconCandidate] {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let entries = root["icons"] as? [Any]
        else { return [] }
        var icons: [IconCandidate] = []
        for case let entry as [String: Any] in entries {
            guard icons.count < 16 else { break }
            guard let src = entry["src"] as? String, let url = iconURL(src, base: base) else { continue }
            let purposes = ((entry["purpose"] as? String) ?? "any").lowercased().split(whereSeparator: \.isWhitespace)
            if !purposes.isEmpty, purposes.allSatisfy({ $0 == "monochrome" }) { continue }
            icons.append(IconCandidate(
                url: url, kind: .manifest, declared: largestSize(in: entry["sizes"] as? String),
                vector: isSVG(type: entry["type"] as? String, url: url)))
        }
        return icons
    }

    // MARK: Parent brand

    /// The brand a site belongs to, as icon numbers of one pack version: `byName` from the site's
    /// name, `byLink` from the domains its home page links to. `ItemIconResolver` shows `byName`
    /// before the site's own icon and `byLink` only when the site has no icon it may show.
    public struct ParentBrand: Codable, Equatable, Sendable {
        public let packVersion: Int
        public let byName: Int?
        public let byLink: Int?

        var isEmpty: Bool { byName == nil && byLink == nil }
    }

    /// The parent brand of the cached host of `url`, without waiting and without any request; nil
    /// when the host was never searched with a pack. Its `packVersion` may be an older pack's.
    public nonisolated func cachedParentBrand(for url: String) -> ParentBrand? {
        guard enabled(), let host = Self.fetchableHost(of: url) else { return nil }
        return cachedBrand(host: host)
    }

    private nonisolated func cachedBrand(host: String) -> ParentBrand? {
        if let hit = brands.withLock({ $0[host] }) { return hit }
        let read = (try? Data(contentsOf: cacheFile(host: host, ext: "brand")))
            .flatMap { try? JSONDecoder().decode(ParentBrand.self, from: $0) }
        // A record written meanwhile (a search that just ended) wins over this read.
        return brands.withLock { memo -> ParentBrand? in
            if memo[host] == nil { memo[host] = .some(read) }
            return memo[host] ?? nil
        }
    }

    /// Whether the host's parent brand must be looked for again: the pack changed since, or it was
    /// never looked for. Never without a pack.
    private func brandOutdated(host: String) -> Bool {
        guard let current = pack() else { return false }
        return cachedBrand(host: host)?.packVersion != current.version
    }

    private func storeBrand(_ brand: ParentBrand, host: String) {
        brands.withLock { $0[host] = .some(brand) }
        if let data = try? JSONEncoder().encode(brand) { write(data, to: cacheFile(host: host, ext: "brand")) }
    }

    /// `ParentBrand` of a home page (and its manifest) for `pack`: the first site name
    /// (`siteNames`) the pack knows as a brand (`IconPack.icon(forBrandName:)`), and the first linked
    /// domain (`linkedDomains`) the pack has an icon for. Never a hosting platform's icon
    /// (`IconPack.mayBeParentBrand`): a portal naming or linking to its software vendor ("Daxko") is
    /// not that vendor's brand.
    static func parentBrand(page: Data, manifest: Data?, host: String, pack: IconPack) -> ParentBrand {
        let names = siteNames(in: page, manifest: manifest)
        let byName = names.lazy.compactMap(pack.number(forBrandName:)).first(where: pack.mayBeParentBrand)
        let byLink = linkedDomains(in: page, host: host, names: names).lazy.compactMap(pack.number(forLinkedDomain:))
            .first(where: pack.mayBeParentBrand)
        return ParentBrand(packVersion: pack.version, byName: byName, byLink: byLink)
    }

    /// Where a title's brand name ends ("Acme | Member Portal").
    static let titleSeparators = [" | ", " - ", " : ", " \u{2013} ", " \u{2014} ", " \u{00B7} "]

    /// Longest site name read, in characters.
    static let maxNameLength = 120

    /// The names a home page gives its site, best first: `og:site_name`, `application-name`, the
    /// manifest's `name` and `short_name` (when it was fetched), then the `<title>` up to its first
    /// separator (`titleSeparators`). HTML entities decoded, spaces collapsed, empty ones dropped.
    static func siteNames(in data: Data, manifest: Data? = nil) -> [String] {
        let html = String(decoding: data, as: UTF8.self)
        var found: [String] = []
        func add(_ raw: String?) {
            guard let raw else { return }
            let clean = decodeEntities(raw).split(whereSeparator: \.isWhitespace).joined(separator: " ")
            guard !clean.isEmpty, clean.count <= maxNameLength * 4, !found.contains(clean) else { return }
            found.append(String(clean.prefix(maxNameLength)))
        }
        var metas: [String: String] = [:]
        for element in tags("meta", in: html) {
            guard let key = (attribute("property", in: element) ?? attribute("name", in: element))?.lowercased(),
                key == "og:site_name" || key == "application-name", metas[key] == nil,
                let content = attribute("content", in: element)
            else { continue }
            metas[key] = content
        }
        add(metas["og:site_name"])
        add(metas["application-name"])
        if let manifest, let root = try? JSONSerialization.jsonObject(with: manifest) as? [String: Any] {
            add(root["name"] as? String)
            add(root["short_name"] as? String)
        }
        if let regex = try? NSRegularExpression(pattern: "<title\\b[^>]{0,4096}>([^<]{1,512})", options: [.caseInsensitive]),
            let match = regex.firstMatch(in: html, range: NSRange(html.startIndex..., in: html)),
            let range = Range(match.range(at: 1), in: html)
        {
            var title = decodeEntities(String(html[range])).split(whereSeparator: \.isWhitespace).joined(separator: " ")
            for separator in titleSeparators {
                if let cut = title.range(of: separator) { title = String(title[..<cut.lowerBound]) }
            }
            add(title)
        }
        return found
    }

    /// The first site name (`siteNames`).
    static func siteName(in data: Data, manifest: Data? = nil) -> String? {
        siteNames(in: data, manifest: manifest).first
    }

    /// Registrable domains a link to which says nothing about the site's brand: social networks,
    /// app stores, analytics, CDNs, payment and captcha providers, standards bodies.
    static let excludedLinkedDomains: Set<String> = [
        "facebook.com", "instagram.com", "x.com", "twitter.com", "linkedin.com", "youtube.com", "tiktok.com",
        "apple.com", "google.com", "googletagmanager.com", "google-analytics.com", "cloudflare.com",
        "cloudfront.net", "akamaihd.net", "gstatic.com", "doubleclick.net", "w3.org", "schema.org", "stripe.com",
        "paypal.com", "adyen.com", "recaptcha.net", "hcaptcha.com",
    ]
    /// Linked domains kept at most.
    static let maxLinkedDomains = 5
    /// Links read at most on one page.
    static let maxLinksRead = 4000
    /// Shortest common start of two names that makes them look like one brand.
    static let sharedPrefixLength = 4

    /// The registrable domains a home page links to (`<a href>`, `<link rel="canonical">`,
    /// `og:url`), most frequent first, at most `maxLinkedDomains`. Kept: the page's canonical or
    /// `og:url` domain, and a domain whose name starts like the host's own name or like one of the
    /// site's `names` (`sharedPrefixLength` characters: `bayclubconnect.com` and `bayclubs.com`).
    /// Never the site's own domain nor `excludedLinkedDomains`; HTTP(S) to public names only.
    static func linkedDomains(in data: Data, host: String, names: [String] = []) -> [String] {
        let html = String(decoding: data, as: UTF8.self)
        let own = registrableDomain(of: host)
        var counts: [String: Int] = [:]
        var order: [String] = []
        var canonical = Set<String>()
        func domain(_ reference: String?) -> String? {
            guard var text = reference.map({ decodeEntities($0).trimmingCharacters(in: .whitespacesAndNewlines) })
            else { return nil }
            if text.hasPrefix("//") { text = "https:" + text }
            guard let components = URLComponents(string: text),
                let scheme = components.scheme?.lowercased(), scheme == "https" || scheme == "http",
                let name = components.host?.lowercased(), isFetchableHost(name),
                let registrable = registrableDomain(of: name), registrable != own,
                !excludedLinkedDomains.contains(registrable)
            else { return nil }
            return registrable
        }
        func count(_ registrable: String) {
            if counts[registrable] == nil { order.append(registrable) }
            counts[registrable, default: 0] += 1
        }
        for element in tags("a", in: html, limit: maxLinksRead) {
            if let found = domain(attribute("href", in: element)) { count(found) }
        }
        for element in tags("link", in: html) {
            guard let rel = attribute("rel", in: element)?.lowercased(),
                rel.split(whereSeparator: \.isWhitespace).contains("canonical"),
                let found = domain(attribute("href", in: element))
            else { continue }
            canonical.insert(found)
            count(found)
        }
        for element in tags("meta", in: html) {
            guard (attribute("property", in: element) ?? attribute("name", in: element))?.lowercased() == "og:url",
                let found = domain(attribute("content", in: element))
            else { continue }
            canonical.insert(found)
            count(found)
        }
        let label = { (domain: String) in IconPack.squash(String(domain.split(separator: ".").first ?? "")) }
        let anchors = ([own.map(label)].compactMap { $0 } + names.flatMap { IconPack.brandKeys($0) + [IconPack.squash($0)] })
            .filter { $0.count >= sharedPrefixLength }
        func related(_ registrable: String) -> Bool {
            if canonical.contains(registrable) { return true }
            let name = label(registrable)
            return anchors.contains { zip($0, name).prefix(while: { $0.0 == $0.1 }).count >= sharedPrefixLength }
        }
        let ranked = order.enumerated().sorted { a, b in
            let (left, right) = (counts[a.element] ?? 0, counts[b.element] ?? 0)
            return left != right ? left > right : a.offset < b.offset
        }
        return Array(ranked.map(\.element).filter(related).prefix(maxLinkedDomains))
    }

    /// The opening tags `<name ...>` of a page (each at most 4096 characters), the first `limit`.
    private static func tags(_ name: String, in html: String, limit: Int = .max) -> [String] {
        guard limit > 0,
            let regex = try? NSRegularExpression(pattern: "<\(name)\\b[^>]{0,4096}>", options: [.caseInsensitive])
        else { return [] }
        var found: [String] = []
        regex.enumerateMatches(in: html, range: NSRange(html.startIndex..., in: html)) { match, _, stop in
            if let match, let range = Range(match.range, in: html) { found.append(String(html[range])) }
            if found.count >= limit { stop.pointee = true }
        }
        return found
    }

    /// `text` with its HTML character references decoded (`&amp;`, `&#39;`, `&#x2019;`...); an
    /// unknown named one is dropped, a malformed numeric one kept as written.
    static func decodeEntities(_ text: String) -> String {
        guard text.contains("&") else { return text }
        let named: [String: Character] = [
            "amp": "&", "lt": "<", "gt": ">", "quot": "\"", "apos": "'", "nbsp": " ", "eacute": "\u{E9}",
            "egrave": "\u{E8}", "agrave": "\u{E0}", "ccedil": "\u{E7}", "rsquo": "\u{2019}", "lsquo": "\u{2018}",
            "ndash": "\u{2013}", "mdash": "\u{2014}", "middot": "\u{B7}", "reg": "\u{AE}", "trade": "\u{2122}",
            "copy": "\u{A9}",
        ]
        var out = ""
        var index = text.startIndex
        while index < text.endIndex {
            if text[index] == "&", let end = text[index...].prefix(12).firstIndex(of: ";") {
                let body = text[text.index(after: index)..<end]
                var decoded: Character?
                if body.hasPrefix("#") {
                    let digits = body.dropFirst()
                    let value = digits.lowercased().hasPrefix("x") ? UInt32(digits.dropFirst(), radix: 16) : UInt32(digits)
                    if let value, value > 0, let scalar = Unicode.Scalar(value) { decoded = Character(scalar) }
                } else if body.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }), !body.isEmpty {
                    guard let known = named[body.lowercased()] else {
                        index = text.index(after: end)
                        continue
                    }
                    decoded = known
                }
                if let decoded {
                    out.append(decoded)
                    index = text.index(after: end)
                    continue
                }
            }
            out.append(text[index])
            index = text.index(after: index)
        }
        return out
    }

    // MARK: Image

    /// A normalized icon and the size of the source it came from.
    struct DecodedIcon: Sendable {
        let png: Data
        /// Largest side of the source image (`iconPixels` for an SVG).
        let sourcePixels: Int
    }

    /// The width and height the first image declares in its header, read without decoding it.
    static func declaredPixelSize(_ data: Data) -> (width: Int, height: Int)? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        return declaredPixelSize(source, at: 0)
    }

    private static func declaredPixelSize(_ source: CGImageSource, at index: Int) -> (width: Int, height: Int)? {
        guard index < CGImageSourceGetCount(source),
            let properties = CGImageSourceCopyPropertiesAtIndex(source, index, nil) as? [CFString: Any],
            let width = (properties[kCGImagePropertyPixelWidth] as? NSNumber)?.intValue,
            let height = (properties[kCGImagePropertyPixelHeight] as? NSNumber)?.intValue
        else { return nil }
        return (width, height)
    }

    /// PNG bytes of `decodeIcon`.
    static func normalizedPNG(_ data: Data) -> Data? {
        decodeIcon(data)?.png
    }

    /// A raster image through ImageIO, or else a safe SVG drawn by the system; nil for anything else.
    static func decodeIcon(_ data: Data) -> DecodedIcon? {
        if let raster = decodeRaster(data) { return raster }
        return renderSVG(data)
    }

    /// Decodes with ImageIO (rejects anything that is not an image, and any image whose declared size
    /// is unknown or above `maxSourcePixels` on a side, before any decode). Of several images (an ICO)
    /// the largest is used. Re-encoded by `squarePNG`.
    static func decodeRaster(_ data: Data) -> DecodedIcon? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
            let type = CGImageSourceGetType(source),
            UTType(type as String)?.conforms(to: .image) == true
        else { return nil }
        var chosen: (index: Int, side: Int)?
        for index in 0..<min(CGImageSourceGetCount(source), 64) {
            guard let size = declaredPixelSize(source, at: index),
                (1...maxSourcePixels).contains(size.width), (1...maxSourcePixels).contains(size.height)
            else { continue }
            let side = max(size.width, size.height)
            if side > chosen?.side ?? 0 { chosen = (index, side) }
        }
        guard let chosen else { return nil }
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceThumbnailMaxPixelSize: min(chosen.side, iconPixels),
        ]
        guard let image = CGImageSourceCreateThumbnailAtIndex(source, chosen.index, options as CFDictionary),
            let png = squarePNG(side: min(iconPixels, chosen.side * 2), aspect: CGSize(width: image.width, height: image.height), draw: { context, rect in
                context.draw(image, in: rect)
            })
        else { return nil }
        return DecodedIcon(png: png, sourcePixels: chosen.side)
    }

    /// A transparent square PNG of `side` pixels, the content fitted and centred with high quality
    /// interpolation.
    static func squarePNG(side: Int, aspect: CGSize, draw: (CGContext, CGRect) -> Void) -> Data? {
        guard side > 0, aspect.width > 0, aspect.height > 0,
            let space = CGColorSpace(name: CGColorSpace.sRGB),
            let context = CGContext(
                data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0, space: space,
                bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
        else { return nil }
        context.clear(CGRect(x: 0, y: 0, width: side, height: side))
        context.interpolationQuality = .high
        let scale = CGFloat(side) / max(aspect.width, aspect.height)
        let width = (aspect.width * scale).rounded(), height = (aspect.height * scale).rounded()
        let rect = CGRect(
            x: ((CGFloat(side) - width) / 2).rounded(), y: ((CGFloat(side) - height) / 2).rounded(),
            width: width, height: height)
        draw(context, rect)
        guard let image = context.makeImage() else { return nil }
        let output = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(output, UTType.png.identifier as CFString, 1, nil)
        else { return nil }
        CGImageDestinationAddImage(destination, image, nil)
        guard CGImageDestinationFinalize(destination) else { return nil }
        return output as Data
    }

    // MARK: SVG

    /// Whether this platform draws SVG with a system API.
    static var rendersSVG: Bool {
        #if os(macOS)
        true
        #else
        false
        #endif
    }

    /// An SVG document that draws without fetching or running anything: starts with markup, has an
    /// `<svg>` root, no DOCTYPE or entity (no expansion bomb), no script, no embedded image, foreign
    /// object or `@import`, and every `href`, `src` or `url()` points to a `#fragment` of the file.
    static func isSafeSVG(_ data: Data) -> Bool {
        let text = String(decoding: data, as: UTF8.self)
        let lowered = text.lowercased()
        guard lowered.drop(while: { $0.isWhitespace || $0 == "\u{FEFF}" }).first == "<",
            lowered.contains("<svg")
        else { return false }
        let banned = ["<!doctype", "<!entity", "<script", "<image", "<foreignobject", "<iframe", "@import"]
        if banned.contains(where: lowered.contains) { return false }
        // Possessive spaces and one branch per quote style: no backtracking around the `#` check.
        let outside = [
            #"(?:href|src)\s*+=\s*+(?:"\s*+(?!#)|'\s*+(?!#)|(?!["'#]))"#,
            #"url\(\s*+(?:"\s*+(?!#)|'\s*+(?!#)|(?!["'#]))"#,
        ]
        for pattern in outside {
            guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return false }
            if regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil { return false }
        }
        return true
    }

    /// A safe SVG (`isSafeSVG`) drawn at `iconPixels` by `NSImage`, nil elsewhere or when it cannot be
    /// drawn.
    static func renderSVG(_ data: Data) -> DecodedIcon? {
        guard rendersSVG, isSafeSVG(data) else { return nil }
        #if os(macOS)
        guard let image = NSImage(data: data), image.size.width > 0, image.size.height > 0 else { return nil }
        let png = squarePNG(side: iconPixels, aspect: image.size) { context, rect in
            let previous = NSGraphicsContext.current
            NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: false)
            image.draw(in: rect)
            NSGraphicsContext.current = previous
        }
        #else
        let png: Data? = nil
        #endif
        return png.map { DecodedIcon(png: $0, sourcePixels: iconPixels) }
    }

    private nonisolated func isImage(_ data: Data) -> Bool {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil) else { return false }
        return CGImageSourceGetCount(source) > 0
    }

    // MARK: Cache

    /// `<sha256 of host>.<version>.<ext>`; `versioned: false` names the files of the 128 px cache.
    private nonisolated func cacheFile(host: String, ext: String, versioned: Bool = true) -> URL {
        let digest = SHA256.hash(data: Data(host.lowercased().utf8))
        let name = digest.map { String(format: "%02x", $0) }.joined()
        let suffix = versioned ? Self.cacheVersion + "." + ext : ext
        return cacheDirectory.appendingPathComponent(name + "." + suffix)
    }

    private func markerAge(host: String) -> TimeInterval? {
        let path = cacheFile(host: host, ext: "miss").path
        guard let date = (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
        else { return nil }
        return Date().timeIntervalSince(date)
    }

    private func write(_ data: Data, to url: URL) {
        try? FileManager.default.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
        #if os(iOS) || os(visionOS)
        let options: Data.WritingOptions = [.atomic, .completeFileProtectionUnlessOpen]
        #else
        let options: Data.WritingOptions = [.atomic]
        #endif
        try? data.write(to: url, options: options)
    }

    /// Drops what the previous cache version left for this host.
    private func removeLegacy(host: String) {
        try? FileManager.default.removeItem(at: cacheFile(host: host, ext: "png", versioned: false))
        try? FileManager.default.removeItem(at: cacheFile(host: host, ext: "miss", versioned: false))
    }

    private func store(_ png: Data, host: String) {
        write(png, to: cacheFile(host: host, ext: "png"))
        try? FileManager.default.removeItem(at: cacheFile(host: host, ext: "miss"))
        removeLegacy(host: host)
    }

    private func markFailure(host: String) {
        write(Data(), to: cacheFile(host: host, ext: "miss"))
        removeLegacy(host: host)
    }
}

/// Lets a request through a redirect on the same host, or once to another host of the same
/// registrable domain (`notion.so` to `www.notion.so`) that is a public name resolving to public
/// addresses only. For the home page (`home`), that one hop may also go to the same name under
/// another suffix (`www.notion.so` to `www.notion.com`), with the same checks. Anything else (HTTP,
/// another site, a second hop) is refused.
private final class RedirectGuard: NSObject, URLSessionTaskDelegate, Sendable {
    let host: String
    let resolver: any HostResolver
    let home: Bool
    /// The host the request moved to, set by the one cross host hop allowed.
    private let moved = Mutex<String?>(nil)

    init(host: String, resolver: any HostResolver, home: Bool) {
        self.host = host
        self.resolver = resolver
        self.home = home
    }

    /// Whether the response may come from `landed`: the host this guard let the request move to.
    func allowed(_ landed: String) -> Bool {
        moved.withLock { $0 == landed }
    }

    func urlSession(
        _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        guard let url = request.url, url.scheme?.lowercased() == "https", let target = url.host?.lowercased()
        else { return nil }
        let current = moved.withLock { $0 } ?? host
        if target == current { return request }
        // One hop to another host of the same site (or, from the home page, of the same name under
        // another suffix), never two.
        let related = SiteIconLoader.sameSite(target, host)
            || (home && SiteIconLoader.sameNameOtherSuffix(target, host))
        guard moved.withLock({ $0 }) == nil, related,
            SiteIconLoader.isFetchableHost(target),
            let addresses = await resolver.addresses(for: target), !addresses.isEmpty,
            addresses.allSatisfy(\.isPublic)
        else { return nil }
        let claimed = moved.withLock { slot -> Bool in
            guard slot == nil else { return false }
            slot = target
            return true
        }
        return claimed ? request : nil
    }
}
