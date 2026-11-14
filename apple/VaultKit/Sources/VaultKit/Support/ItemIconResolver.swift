import Foundation
import Synchronization

/// Where an item's icon comes from, best first (docs/icon-pack.md, "Ordre de recherche"):
///
/// 1. The icon the person chose for the item (`custom_icon`), decrypted from the vault into
///    `custom` (`CustomIconStore`, memory only): callers pass its `CustomIconKey`. One that does not
///    load (not synced yet) falls through to the rest of this order.
/// 2. The icon pack (`IconPackStore`): the item's host, then its parent names down to the
///    registrable domain. Read from a file on this device: no request at all.
/// 3. The icon pack by the item's title, when it is a brand's name ("Reddit", "Burger King") or a
///    web address: an item with no address, or one the pack does not know, still finds its brand.
/// 4. The site's own icon (`SiteIconLoader`, fetched from the item's site only), shown only when
///    its source was at least 32 px on its longest side; a source of 32 to 63 px (stored at 64 to
///    127 px) is drawn bare by `ItemIcon`, never stretched. A smaller one is a blur. Never a hosting
///    platform's icon (the pack's `rejects`), not even one cached before the pack knew it.
/// 5. Nothing: `ItemIcon` then draws the monogram tile (a login with a title) or the category
///    artwork.
///
/// A host the pack covers is never fetched from its site, not even to prefetch. With
/// "Website Icons" off, no icon of either kind is shown and nothing is fetched.
public final class ItemIconResolver: Sendable {
    /// Smallest source (pixels, longest side) of a site icon that is shown.
    public static let minSitePixels = 32

    public let pack: IconPackStore?
    public let site: SiteIconLoader
    /// The chosen icons; nil where no vault is open (previews, tests).
    public let custom: CustomIconStore?
    private let enabled: @Sendable () -> Bool
    /// Per host: the cached site icon last checked against the pack's rejects (and that pack's
    /// version), and whether it was refused. A row asks on every frame: each icon is hashed once.
    private let checked = Mutex<[String: (png: Data, version: Int, rejected: Bool)]>([:])

    public init(
        pack: IconPackStore?, site: SiteIconLoader, custom: CustomIconStore? = nil,
        enabled: @escaping @Sendable () -> Bool
    ) {
        self.pack = pack
        self.site = site
        self.custom = custom
        self.enabled = enabled
    }

    /// The resolver of the app or of an extension: the pack shipped in the app (`bundledPack`) and
    /// the shared pack folder (`SharedContainer.iconPackFolder`), the site icon cache in this
    /// process's caches, and `custom` for the chosen icons.
    public static func live(
        settings: VaultSettings, container: SharedContainer = .resolve(), bundle: Bundle = .main,
        custom: CustomIconStore? = nil
    ) -> ItemIconResolver {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        let enabled: @Sendable () -> Bool = { settings.siteIconsEnabled }
        let pack = IconPackStore(baseline: IconPackStore.bundledPack(in: bundle), directory: container.iconPackFolder)
        return ItemIconResolver(
            pack: pack,
            site: SiteIconLoader(
                cacheDirectory: caches.appendingPathComponent("OnePass/SiteIcons", isDirectory: true), enabled: enabled,
                rejects: { pack.pack()?.rejects ?? [] }),
            custom: custom, enabled: enabled)
    }

    /// The order above, for one item.
    public static func pick(chosen: Data?, pack: Data?, site: Data?) -> Data? {
        chosen ?? pack ?? site.flatMap(sharpEnough)
    }

    /// The icon already on this device (chosen, pack, else the cached site icon), without waiting
    /// and without any request: what a row shows on its first frame.
    public func cachedIcon(for url: String, chosen: Data? = nil) -> Data? {
        cachedIcon(for: url, title: "", chosen: chosen)
    }

    /// Same, with the item's title for the pack's brand names (an item without a web address too).
    public func cachedIcon(for url: String?, title: String, chosen: Data? = nil) -> Data? {
        if let chosen { return chosen }
        guard enabled() else { return nil }
        if let url, let packed = packIcon(for: url) { return packed }
        if let named = pack?.icon(forTitle: title)?.data { return named }
        guard let url else { return nil }
        return Self.pick(chosen: nil, pack: nil, site: notRejected(site.cachedIcon(for: url), url: url))
    }

    /// Same, the chosen icon first when it is in memory. A row shows this on its first frame and
    /// calls `icon(for:title:custom:)` (or `custom.prefetch`) in its task, then reads it again.
    public func cachedIcon(for url: String?, title: String, custom key: CustomIconKey?) -> Data? {
        cachedIcon(for: url, title: title, chosen: chosenIcon(key))
    }

    /// The icon of `url`, fetching the site's own icon only when the pack has none.
    public func icon(for url: String, chosen: Data? = nil) async -> Data? {
        await icon(for: url, title: "", chosen: chosen)
    }

    /// Same, with the item's title (`cachedIcon(for:title:chosen:)`).
    public func icon(for url: String?, title: String, chosen: Data? = nil) async -> Data? {
        if let chosen { return chosen }
        guard enabled() else { return nil }
        if let url, let packed = packIcon(for: url) { return packed }
        if let named = pack?.icon(forTitle: title)?.data { return named }
        guard let url else { return nil }
        return Self.pick(chosen: nil, pack: nil, site: notRejected(await site.icon(for: url), url: url))
    }

    /// Same, loading the chosen icon from the vault first (`CustomIconStore.prefetch`): a chosen
    /// icon that does not load gives the automatic one.
    public func icon(for url: String?, title: String, custom key: CustomIconKey?) async -> Data? {
        if let key, let custom { await custom.prefetch(key) }
        return await icon(for: url, title: title, chosen: chosenIcon(key))
    }

    private func chosenIcon(_ key: CustomIconKey?) -> Data? {
        guard let key, let custom else { return nil }
        return custom.cached(key)
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

    /// `png`, the site icon of `url`, unless it is a hosting platform's icon (the pack's `rejects`):
    /// one cached before the pack had that reject is refused here. Hashed once per host and icon.
    func notRejected(_ png: Data?, url: String) -> Data? {
        guard let png, let current = pack?.pack(), !current.rejects.isEmpty else { return png }
        let key = Self.host(of: url) ?? url
        if let memo = checked.withLock({ $0[key] }), memo.version == current.version, memo.png == png {
            return memo.rejected ? nil : png
        }
        let rejected = IconPack.isRejected(png, by: current.rejects)
        checked.withLock { $0[key] = (png, current.version, rejected) }
        return rejected ? nil : png
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

    /// The registrable domain of an item's address (`https://accounts.example.co.uk/login` gives
    /// `example.co.uk`): the seed of its monogram color, so every item of one site matches. An IP
    /// address or a single-label host (`localhost`, `nas`) is its own domain. Nil for no address,
    /// a scheme other than http(s), or a bare public suffix.
    public static func registrableDomain(_ url: String?) -> String? {
        guard let url, let host = host(of: url) else { return nil }
        let isAddress = host.contains(":") || host.allSatisfy { $0.isNumber || $0 == "." }
        if isAddress || !host.contains(".") { return host }
        return SiteIconLoader.registrableDomain(of: host)
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
