import Foundation

/// Whether the system identity store is behind the vault, readable by the app and by the AutoFill
/// provider (the settings suite both share), one pair of marks per account.
///
/// `wanted` changes each time the identity set may have changed (a write, a sync commit, a setting);
/// `published` is the `wanted` a successful replacement of the store was read under. Different, or
/// nothing published yet: the store is behind, and the next unlock, in the app or in the provider,
/// publishes. The marks are random: nothing about the identities is stored.
public struct IdentityPublishLedger: Sendable {
    private let settings: VaultSettings

    public init(settings: VaultSettings) {
        self.settings = settings
    }

    static let wantedKey = "onepass.autofill.identitiesWanted"
    static let publishedKey = "onepass.autofill.identitiesPublished"

    private var defaults: UserDefaults { settings.baseDefaults }

    private func key(_ name: String) -> String {
        name + (settings.scope.map { ".\($0)" } ?? "")
    }

    /// The mark a publication is made under. Read it before the identities: a change made while
    /// they are read then leaves the store behind.
    public var generation: String {
        defaults.string(forKey: key(Self.wantedKey)) ?? markChanged()
    }

    /// The identity set may have changed: behind until a publication read after this call ends.
    @discardableResult
    public func markChanged() -> String {
        let mark = UUID().uuidString
        defaults.set(mark, forKey: key(Self.wantedKey))
        return mark
    }

    /// The store was replaced with identities read under `generation`.
    public func markPublished(_ generation: String) {
        defaults.set(generation, forKey: key(Self.publishedKey))
    }

    public var isBehind: Bool {
        guard let published = defaults.string(forKey: key(Self.publishedKey)) else { return true }
        return published != defaults.string(forKey: key(Self.wantedKey))
    }

    /// The store was emptied (setting off, account erased): nothing is published any more.
    public func reset() {
        defaults.removeObject(forKey: key(Self.publishedKey))
    }
}
