import Foundation

/// A `UserDefaults` seen through a key prefix (multi-account spec 6, ruling P12): the primary account
/// reads and writes its keys as they always were (`onepass.*`, empty prefix); an added account prefixes
/// every key with `onepass.acct.<slot>.`, in the same shared suite, so the AutoFill extension reads it
/// too. It has the `UserDefaults` methods `VaultSettings` uses, so every setting, including the ones
/// other work adds later, goes through the prefix.
public struct ScopedDefaults: @unchecked Sendable {
    public let base: UserDefaults
    public let prefix: String

    /// The prefix of an added account's settings.
    public static func prefix(forSlot slot: String) -> String { "onepass.acct.\(slot)." }

    public init(_ base: UserDefaults, prefix: String = "") {
        self.base = base
        self.prefix = prefix
    }

    private func k(_ key: String) -> String { prefix + key }

    public func object(forKey key: String) -> Any? { base.object(forKey: k(key)) }
    public func string(forKey key: String) -> String? { base.string(forKey: k(key)) }
    public func bool(forKey key: String) -> Bool { base.bool(forKey: k(key)) }
    public func integer(forKey key: String) -> Int { base.integer(forKey: k(key)) }
    public func double(forKey key: String) -> Double { base.double(forKey: k(key)) }
    public func data(forKey key: String) -> Data? { base.data(forKey: k(key)) }
    public func array(forKey key: String) -> [Any]? { base.array(forKey: k(key)) }
    public func stringArray(forKey key: String) -> [String]? { base.stringArray(forKey: k(key)) }
    public func dictionary(forKey key: String) -> [String: Any]? { base.dictionary(forKey: k(key)) }
    public func set(_ value: Any?, forKey key: String) { base.set(value, forKey: k(key)) }
    public func set(_ value: Bool, forKey key: String) { base.set(value, forKey: k(key)) }
    public func set(_ value: Int, forKey key: String) { base.set(value, forKey: k(key)) }
    public func set(_ value: Double, forKey key: String) { base.set(value, forKey: k(key)) }
    public func removeObject(forKey key: String) { base.removeObject(forKey: k(key)) }

    /// Removes every key of this scope (an added account taken off the device). The primary scope
    /// (empty prefix) is never wiped this way.
    public func removeAll() {
        guard !prefix.isEmpty else { return }
        for key in base.dictionaryRepresentation().keys where key.hasPrefix(prefix) {
            base.removeObject(forKey: key)
        }
    }
}
