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

/// Loads site icons straight from the item's own site. HTTPS only, same host only, public host
/// names only (never an IP literal, `localhost`, a single-label name or a local network suffix such as
/// `.local`, `.lan`, `.home.arpa` or `.internal`: no LAN probing), and the name must resolve to public
/// addresses only (checked before any request: no private, loopback, link-local, CGNAT, unique-local
/// or multicast address). 256 KiB at most per response, no cookies, image type checked by ImageIO,
/// declared size checked before any decode, cached by host hash, failures remembered for a week.
///
/// Where the icon comes from, best first: the home page's `<link>` icons (`apple-touch-icon`,
/// `apple-touch-icon-precomposed`, `icon`, `shortcut icon`) and the icons of its web app manifest
/// (same host), ranked by the size they declare (SVG first, then the largest `sizes`); then
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
/// When the item's own host yields nothing (`dashboard.stripe.com`, `notion.so`), its registrable
/// domain (`stripe.com`, never a bare public suffix: `registrableDomain`) is tried, then `www.` plus
/// that domain, each with every check above (public name, public addresses, HTTPS, caps). The icon
/// found is cached under the item's host too. A redirect is followed only on the same host, or once
/// to another host of the same registrable domain (`notion.so` to `www.notion.so`) whose addresses
/// are public. The home page alone may instead make that one hop to the same name under another
/// suffix (`www.notion.so` to `www.notion.com`, `exemple.fr` to `exemple.com`). The rest of that
/// search then runs on the host it landed on.
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
    /// A source this large ends the search.
    static let goodPixels = 128
    /// Below this a source is a last resort.
    static let tinyPixels = 48
    /// Images fetched per host at most (on top of the home page and the manifest).
    static let maxImageAttempts = 6
    /// Version in the cache file names: bumping it refetches every icon once.
    static let cacheVersion = "v2"

    private let cacheDirectory: URL
    private let session: URLSession
    private let resolver: any HostResolver
    private let enabled: @Sendable () -> Bool
    private var inFlight: [String: Task<Data?, Never>] = [:]

    public init(
        cacheDirectory: URL, session: URLSession = .ephemeralNoCookies,
        resolver: any HostResolver = SystemHostResolver(),
        enabled: @escaping @Sendable () -> Bool
    ) {
        self.cacheDirectory = cacheDirectory
        self.session = session
        self.resolver = resolver
        self.enabled = enabled
    }

    /// PNG bytes of the site's icon, or nil (disabled, not HTTPS, no icon, recently failed).
    public func icon(for url: String) async -> Data? {
        guard enabled() else { return nil }
        guard let components = URLComponents(string: url.trimmingCharacters(in: .whitespacesAndNewlines)),
            components.scheme?.lowercased() == "https",
            let host = components.host?.lowercased(), !host.isEmpty, Self.isFetchableHost(host)
        else { return nil }

        if let cached = try? Data(contentsOf: cacheFile(host: host, ext: "png")), isImage(cached) {
            return cached
        }
        if let age = markerAge(host: host), age < Self.failureLifetime { return nil }

        if let task = inFlight[host] { return await task.value }
        let task = Task { await self.fetchAndStore(host: host) }
        inFlight[host] = task
        let result = await task.value
        inFlight[host] = nil
        return result
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

    /// The hosts asked, in order: the item's own, its registrable domain, then `www.` plus that
    /// domain (each once, never a bare public suffix).
    static func siteHosts(for host: String) -> [String] {
        var name = host.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        var hosts = [name]
        if let domain = registrableDomain(of: name) {
            for candidate in [domain, "www." + domain] where !hosts.contains(candidate) {
                hosts.append(candidate)
            }
        }
        return hosts.filter(isFetchableHost)
    }

    /// Searches the item's host, then its parent domain (`siteHosts`); the icon found is stored
    /// under the item's host. A failure is remembered only when every host was really asked.
    private func fetchAndStore(host: String) async -> Data? {
        let hosts = Self.siteHosts(for: host)
        for (index, site) in hosts.enumerated() {
            switch await attempt(site, remember: index > 0) {
            case .icon(let png):
                if site != host { store(png, host: host) }
                return png
            case .miss:
                continue
            case .offline:
                // Says nothing about the site: not remembered, the next display asks again.
                return nil
            case .refused:
                // The item's own name points at a private address: no parent is asked.
                if index == 0 {
                    markFailure(host: host)
                    return nil
                }
            }
        }
        markFailure(host: host)
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
    /// parent domain other items share); the item's host is written by the caller.
    private func attempt(_ host: String, remember: Bool) async -> Attempt {
        if remember {
            if let cached = try? Data(contentsOf: cacheFile(host: host, ext: "png")), isImage(cached) {
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
            if let manifest = links.manifest, let json = await get(manifest, host: site, truncate: false, offline: &offline) {
                candidates += Self.manifestIcons(in: json.data, base: json.url, host: site)
            }
        }
        candidates += Self.wellKnownCandidates(host: site)

        var best: DecodedIcon?
        var attempts = 0
        for candidate in Self.ranked(candidates) {
            if let best, best.sourcePixels >= Self.goodPixels { break }
            guard attempts < Self.maxImageAttempts else { break }
            // A size the site declares that cannot beat what is already in hand is not fetched.
            if let best, !candidate.vector, let declared = candidate.declared, declared <= best.sourcePixels {
                continue
            }
            attempts += 1
            guard let fetched = await get(candidate.url, host: site, truncate: false, offline: &offline),
                let decoded = Self.decodeIcon(fetched.data)
            else { continue }
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

    /// Resolves a reference against `base`: HTTPS on `host` only, nil otherwise.
    private static func sameHost(_ reference: String, base: URL, host: String) -> URL? {
        guard let url = URL(string: reference.trimmingCharacters(in: .whitespacesAndNewlines), relativeTo: base)?
            .absoluteURL,
            url.scheme?.lowercased() == "https", url.host?.lowercased() == host
        else { return nil }
        return url
    }

    // MARK: HTML

    /// Icons named by `<link>` tags (at most 16) and the web app manifest, same host and HTTPS only.
    static func pageLinks(in data: Data, base: URL, host: String) -> (icons: [IconCandidate], manifest: URL?) {
        let html = String(decoding: data, as: UTF8.self)
        guard let tag = try? NSRegularExpression(pattern: "<link\\b[^>]*>", options: [.caseInsensitive])
        else { return ([], nil) }
        var icons: [IconCandidate] = []
        var manifest: URL?
        for match in tag.matches(in: html, range: NSRange(html.startIndex..., in: html)) {
            guard let r = Range(match.range, in: html) else { continue }
            let element = String(html[r])
            guard let relValue = attribute("rel", in: element), let link = attribute("href", in: element),
                let url = sameHost(link, base: base, host: host)
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
                if rels.contains("manifest"), manifest == nil { manifest = url }
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
    private static func attribute(_ name: String, in element: String) -> String? {
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

    /// The `icons` of a web app manifest (at most 16), same host and HTTPS only. Monochrome icons are
    /// left out: they are silhouettes.
    static func manifestIcons(in data: Data, base: URL, host: String) -> [IconCandidate] {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let entries = root["icons"] as? [Any]
        else { return [] }
        var icons: [IconCandidate] = []
        for case let entry as [String: Any] in entries {
            guard icons.count < 16 else { break }
            guard let src = entry["src"] as? String, let url = sameHost(src, base: base, host: host) else { continue }
            let purposes = ((entry["purpose"] as? String) ?? "any").lowercased().split(whereSeparator: \.isWhitespace)
            if !purposes.isEmpty, purposes.allSatisfy({ $0 == "monochrome" }) { continue }
            icons.append(IconCandidate(
                url: url, kind: .manifest, declared: largestSize(in: entry["sizes"] as? String),
                vector: isSVG(type: entry["type"] as? String, url: url)))
        }
        return icons
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

    private func isImage(_ data: Data) -> Bool {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil) else { return false }
        return CGImageSourceGetCount(source) > 0
    }

    // MARK: Cache

    /// `<sha256 of host>.<version>.<ext>`; `versioned: false` names the files of the 128 px cache.
    private func cacheFile(host: String, ext: String, versioned: Bool = true) -> URL {
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
