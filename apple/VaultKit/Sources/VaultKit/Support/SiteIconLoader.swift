import CryptoKit
import Foundation
import ImageIO
import UniformTypeIdentifiers

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
/// names only (never an IP literal, `localhost`, a `.local` or single-label name: no LAN probing),
/// 256 KiB at most per response, no cookies, image type checked by ImageIO, declared size checked
/// before any decode, cached by host hash.
public actor SiteIconLoader {
    static let maxBytes = 256 * 1024
    /// Largest declared width or height decoded: a small file can declare a huge bitmap.
    static let maxSourcePixels = 4096
    static let failureLifetime: TimeInterval = 7 * 24 * 3600
    static let iconPixels = 128

    private let cacheDirectory: URL
    private let session: URLSession
    private let enabled: @Sendable () -> Bool
    private var inFlight: [String: Task<Data?, Never>] = [:]

    public init(
        cacheDirectory: URL, session: URLSession = .ephemeralNoCookies,
        enabled: @escaping @Sendable () -> Bool
    ) {
        self.cacheDirectory = cacheDirectory
        self.session = session
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

    /// A public DNS name: not an IP literal (v4, in any of the shorthand forms resolvers accept, or
    /// v6), not `localhost`, not a `.local` (Bonjour) name, not a single label (a LAN device name).
    static func isFetchableHost(_ host: String) -> Bool {
        var name = host.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty, !name.contains(":"), !name.hasPrefix("[") else { return false }
        if name == "localhost" || name.hasSuffix(".localhost") || name.hasSuffix(".local") { return false }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, labels.allSatisfy({ !$0.isEmpty }), let last = labels.last else { return false }
        // No top-level domain is numeric: `10.0.0.1`, `127.1`, `0x7f.1` or `192.168.1.0x1` are addresses.
        if last.allSatisfy(\.isNumber) { return false }
        if last.hasPrefix("0x"), last.dropFirst(2).allSatisfy(\.isHexDigit) { return false }
        return true
    }

    // MARK: Fetching

    private enum Fetched {
        case data(Data)
        case miss
        case offline
    }

    private func fetchAndStore(host: String) async -> Data? {
        var offline = false
        var found: Data?
        var candidates: [URL] = [
            URL(string: "https://\(host)/apple-touch-icon.png"),
            URL(string: "https://\(host)/favicon.ico"),
        ].compactMap { $0 }

        var triedPage = false
        var index = 0
        while index < candidates.count, found == nil {
            switch await fetch(candidates[index], host: host, truncate: false) {
            case .data(let data): found = Self.normalizedPNG(data)
            case .miss: break
            case .offline: offline = true
            }
            index += 1
            if index == candidates.count, !triedPage, found == nil {
                triedPage = true
                if let home = URL(string: "https://\(host)/") {
                    switch await fetch(home, host: host, truncate: true) {
                    case .data(let html):
                        candidates.append(contentsOf: Self.iconLinks(in: html, base: home, host: host))
                    case .miss: break
                    case .offline: offline = true
                    }
                }
            }
        }

        if let found {
            store(found, host: host)
            return found
        }
        // Being offline says nothing about the site: do not remember it as a failure.
        if !offline { markFailure(host: host) }
        return nil
    }

    /// GET with a hard size cap. Misses on non 2xx, a redirect off HTTPS or off the host, or
    /// (unless truncating, for the HTML page) a body over the cap.
    private func fetch(_ url: URL, host: String, truncate: Bool) async -> Fetched {
        var request = URLRequest(url: url)
        request.httpShouldHandleCookies = false
        do {
            let (bytes, response) = try await session.bytes(for: request, delegate: RedirectGuard(host: host))
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
                http.url?.scheme?.lowercased() == "https", http.url?.host?.lowercased() == host
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
            return .data(data)
        } catch let error as URLError where [.notConnectedToInternet, .networkConnectionLost, .cancelled].contains(error.code) {
            return .offline
        } catch {
            return .miss
        }
    }

    // MARK: HTML

    /// Icon URLs from `<link rel="...icon..." href>` tags, same host and HTTPS only.
    static func iconLinks(in data: Data, base: URL, host: String) -> [URL] {
        let html = String(decoding: data, as: UTF8.self)
        guard let tag = try? NSRegularExpression(pattern: "<link\\b[^>]*>", options: [.caseInsensitive]),
            let rel = try? NSRegularExpression(
                pattern: "\\brel\\s*=\\s*[\"']?([^\"'>]*)", options: [.caseInsensitive]),
            let href = try? NSRegularExpression(
                pattern: "\\bhref\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)')", options: [.caseInsensitive])
        else { return [] }
        func group(_ regex: NSRegularExpression, _ string: String, _ names: [Int]) -> String? {
            let range = NSRange(string.startIndex..., in: string)
            guard let match = regex.firstMatch(in: string, range: range) else { return nil }
            for n in names {
                if let r = Range(match.range(at: n), in: string) { return String(string[r]) }
            }
            return nil
        }
        var urls: [URL] = []
        for match in tag.matches(in: html, range: NSRange(html.startIndex..., in: html)) {
            guard let r = Range(match.range, in: html) else { continue }
            let element = String(html[r])
            guard let relValue = group(rel, element, [1]),
                relValue.lowercased().split(whereSeparator: \.isWhitespace).contains(where: { $0.hasSuffix("icon") }),
                let link = group(href, element, [1, 2]),
                let resolved = URL(string: link.trimmingCharacters(in: .whitespaces), relativeTo: base)?.absoluteURL,
                resolved.scheme?.lowercased() == "https", resolved.host?.lowercased() == host
            else { continue }
            if !urls.contains(resolved) { urls.append(resolved) }
            if urls.count >= 3 { break }
        }
        return urls
    }

    // MARK: Image

    /// The width and height the first image declares in its header, read without decoding it.
    static func declaredPixelSize(_ data: Data) -> (width: Int, height: Int)? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        return declaredPixelSize(source)
    }

    private static func declaredPixelSize(_ source: CGImageSource) -> (width: Int, height: Int)? {
        guard CGImageSourceGetCount(source) > 0,
            let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
            let width = (properties[kCGImagePropertyPixelWidth] as? NSNumber)?.intValue,
            let height = (properties[kCGImagePropertyPixelHeight] as? NSNumber)?.intValue
        else { return nil }
        return (width, height)
    }

    /// Decodes with ImageIO (rejects anything that is not an image, or whose declared size is unknown
    /// or above `maxSourcePixels` on a side, before any decode) and re-encodes as a PNG no larger
    /// than `iconPixels`.
    static func normalizedPNG(_ data: Data) -> Data? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
            CGImageSourceGetCount(source) > 0,
            let type = CGImageSourceGetType(source),
            UTType(type as String)?.conforms(to: .image) == true,
            let size = declaredPixelSize(source),
            (1...maxSourcePixels).contains(size.width), (1...maxSourcePixels).contains(size.height)
        else { return nil }
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceThumbnailMaxPixelSize: iconPixels,
        ]
        guard let image = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary),
            image.width > 0, image.height > 0
        else { return nil }
        let output = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(
            output, UTType.png.identifier as CFString, 1, nil)
        else { return nil }
        CGImageDestinationAddImage(destination, image, nil)
        guard CGImageDestinationFinalize(destination) else { return nil }
        return output as Data
    }

    private func isImage(_ data: Data) -> Bool {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil) else { return false }
        return CGImageSourceGetCount(source) > 0
    }

    // MARK: Cache

    private func cacheFile(host: String, ext: String) -> URL {
        let digest = SHA256.hash(data: Data(host.lowercased().utf8))
        let name = digest.map { String(format: "%02x", $0) }.joined()
        return cacheDirectory.appendingPathComponent(name + "." + ext)
    }

    private func markerAge(host: String) -> TimeInterval? {
        let path = cacheFile(host: host, ext: "miss").path
        guard let date = (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
        else { return nil }
        return Date().timeIntervalSince(date)
    }

    private func write(_ data: Data, to url: URL) {
        try? FileManager.default.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
        #if os(iOS)
        let options: Data.WritingOptions = [.atomic, .completeFileProtectionUnlessOpen]
        #else
        let options: Data.WritingOptions = [.atomic]
        #endif
        try? data.write(to: url, options: options)
    }

    private func store(_ png: Data, host: String) {
        write(png, to: cacheFile(host: host, ext: "png"))
        try? FileManager.default.removeItem(at: cacheFile(host: host, ext: "miss"))
    }

    private func markFailure(host: String) {
        write(Data(), to: cacheFile(host: host, ext: "miss"))
    }
}

/// Refuses any redirect that leaves HTTPS or the original host.
private final class RedirectGuard: NSObject, URLSessionTaskDelegate, Sendable {
    let host: String
    init(host: String) { self.host = host }

    func urlSession(
        _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        guard let url = request.url, url.scheme?.lowercased() == "https",
            url.host?.lowercased() == host
        else { return nil }
        return request
    }
}
