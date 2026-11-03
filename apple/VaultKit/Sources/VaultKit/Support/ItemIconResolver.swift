import Foundation

/// Where an item's icon comes from, best first (docs/icon-pack.md, "Ordre de recherche"):
///
/// 1. The icon the person chose for the item. The core keeps one (`custom_icon`) but no screen
///    sets it and the bridge does not expose it yet: callers pass it as `chosen` once it is.
/// 2. The icon pack (`IconPackStore`): the item's host, then its parent names down to the
///    registrable domain. Read from a file on this device: no request at all.
/// 3. The site's own icon (`SiteIconLoader`, fetched from the item's site only), shown only when
///    its source was at least `minSitePixels` on its longest side. A smaller one stretched to a
///    tile is a blur.
/// 4. Nothing: `ItemIcon` then draws the monogram tile (a login with a title) or the category
///    artwork.
///
/// A host the pack covers is never fetched from its site, not even to prefetch. With
/// "Website Icons" off, no icon of either kind is shown and nothing is fetched.
public final class ItemIconResolver: Sendable {
    /// Smallest source (pixels, longest side) of a site icon that is shown.
    public static let minSitePixels = 64

    public let pack: IconPackStore?
    public let site: SiteIconLoader
    private let enabled: @Sendable () -> Bool

    public init(pack: IconPackStore?, site: SiteIconLoader, enabled: @escaping @Sendable () -> Bool) {
        self.pack = pack
        self.site = site
        self.enabled = enabled
    }

    /// The resolver of the app or of an extension: the pack shipped in the app (`bundledPack`) and
    /// the shared pack folder (`SharedContainer.iconPackFolder`), the site icon cache in this
    /// process's caches.
    public static func live(
        settings: VaultSettings, container: SharedContainer = .resolve(), bundle: Bundle = .main
    ) -> ItemIconResolver {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        let enabled: @Sendable () -> Bool = { settings.siteIconsEnabled }
        return ItemIconResolver(
            pack: IconPackStore(baseline: IconPackStore.bundledPack(in: bundle), directory: container.iconPackFolder),
            site: SiteIconLoader(
                cacheDirectory: caches.appendingPathComponent("OnePass/SiteIcons", isDirectory: true), enabled: enabled),
            enabled: enabled)
    }

    /// The order above, for one item.
    public static func pick(chosen: Data?, pack: Data?, site: Data?) -> Data? {
        chosen ?? pack ?? site.flatMap(sharpEnough)
    }

    /// The icon already on this device (chosen, pack, else the cached site icon), without waiting
    /// and without any request: what a row shows on its first frame.
    public func cachedIcon(for url: String, chosen: Data? = nil) -> Data? {
        if let chosen { return chosen }
        guard enabled() else { return nil }
        if let packed = packIcon(for: url) { return packed }
        return Self.pick(chosen: nil, pack: nil, site: site.cachedIcon(for: url))
    }

    /// The icon of `url`, fetching the site's own icon only when the pack has none.
    public func icon(for url: String, chosen: Data? = nil) async -> Data? {
        if let chosen { return chosen }
        guard enabled() else { return nil }
        if let packed = packIcon(for: url) { return packed }
        return Self.pick(chosen: nil, pack: nil, site: await site.icon(for: url))
    }

    /// Loads in the background the site icons of the hosts the pack does not cover.
    public func prefetch(_ urls: [String]) async {
        guard enabled() else { return }
        await site.prefetch(urls.filter { packIcon(for: $0) == nil })
    }

    /// At launch: shares the shipped pack with the extensions, then asks for a newer signed pack
    /// when one is due (never while the public key is empty, never with icons off).
    public func maintainPack() async {
        guard let pack else { return }
        _ = pack.pack()
        await pack.shareBaseline()
        guard enabled() else { return }
        await pack.refreshIfDue()
    }

    private func packIcon(for url: String) -> Data? {
        guard let pack, let host = Self.host(of: url) else { return nil }
        return pack.icon(forHost: host)?.data
    }

    /// The host of an `http`, `https` or scheme-less URL (`example.com/login`), lowercased.
    static func host(of url: String) -> String? {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let components = URLComponents(string: trimmed.contains("://") ? trimmed : "https://" + trimmed)
        guard let scheme = components?.scheme?.lowercased(), scheme == "https" || scheme == "http",
            let host = components?.host?.lowercased(), !host.isEmpty
        else { return nil }
        return host
    }

    /// `SiteIconLoader` stores a square PNG of `min(256, 2 x source)` pixels: a side of at least
    /// twice `minSitePixels` means a source of at least `minSitePixels`.
    static func sharpEnough(_ png: Data) -> Data? {
        guard let size = SiteIconLoader.declaredPixelSize(png), max(size.width, size.height) >= 2 * minSitePixels
        else { return nil }
        return png
    }
}

extension IconPackStore {
    /// File name of the pack shipped in the app's resources.
    public static let bundledName = "onepass-icons"

    /// The pack shipped in `bundle`, or, from an app extension, in the app that contains it
    /// (`<App>.app/PlugIns/<Ext>.appex` on iOS, `<App>.app/Contents/PlugIns/<Ext>.appex` on macOS).
    public static func bundledPack(in bundle: Bundle = .main) -> URL? {
        if let url = bundle.url(forResource: bundledName, withExtension: "bin") { return url }
        guard bundle.bundleURL.pathExtension == "appex" else { return nil }
        var url = bundle.bundleURL.deletingLastPathComponent()
        while url.pathComponents.count > 1, url.pathExtension != "app" {
            url = url.deletingLastPathComponent()
        }
        guard url.pathExtension == "app" else { return nil }
        return Bundle(url: url)?.url(forResource: bundledName, withExtension: "bin")
    }
}

extension SharedContainer {
    /// Where the downloaded (and shared) icon pack lives: the App Group's caches, which the app
    /// and its extensions all read; this process's caches without a shared container.
    public var iconPackFolder: URL {
        let caches =
            isShared
            ? root.appendingPathComponent("Library/Caches", isDirectory: true)
            : FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        return caches.appendingPathComponent("OnePass/IconPack", isDirectory: true)
    }
}
