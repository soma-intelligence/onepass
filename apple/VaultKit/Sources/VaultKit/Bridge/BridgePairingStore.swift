import Foundation
import OnePassCore

/// The bridge's pairings (the Mac app's `BrowserBridge`, the iOS Safari extension's
/// `SafariExtensionVault`), in one keychain item (JSON list, keys in base64), `WhenUnlockedThisDeviceOnly`,
/// never synchronized. Written from bridge threads: every read-modify-write holds the lock.
final class BridgePairingStore: @unchecked Sendable {
    static let service = "me.somalabs.onepass.bridge"
    static let key = "pairings"
    /// Extension ids the user forgot (JSON list): no automatic pairing for them.
    static let blockedKey = "auto-blocked"
    /// `last_used` is written back at most this often per pairing.
    static let touchInterval: UInt64 = 3600

    private let keychain: any KeychainStore
    private let lock = NSLock()

    init(keychain: any KeychainStore) {
        self.keychain = keychain
    }

    private struct Stored: Codable {
        var pairingId: String
        var key: String
        var extName: String
        var browser: String
        var extensionId: String
        /// Absent in items written before automatic pairing, and after a code pairing.
        var verifiedBrowser: String?
        var createdAt: UInt64
        var lastUsed: UInt64
    }

    private func read() -> [Stored] {
        guard let data = try? keychain.read(Self.key) else { return [] }
        return (try? JSONDecoder().decode([Stored].self, from: data)) ?? []
    }

    private func write(_ list: [Stored]) {
        guard let data = try? JSONEncoder().encode(list) else { return }
        try? keychain.write(Self.key, data)
    }

    func load() -> [FfiBridgePairing] {
        lock.lock()
        defer { lock.unlock() }
        return read().compactMap { s in
            guard let key = Data(base64Encoded: s.key), key.count == 32 else { return nil }
            return FfiBridgePairing(
                pairingId: s.pairingId, key: key, extName: s.extName, browser: s.browser,
                extensionId: s.extensionId, verifiedBrowser: s.verifiedBrowser ?? "",
                createdAt: s.createdAt, lastUsed: s.lastUsed)
        }
    }

    func add(_ p: FfiBridgePairing) {
        lock.lock()
        defer { lock.unlock() }
        var list = read().filter { $0.pairingId != p.pairingId }
        list.append(
            Stored(
                pairingId: p.pairingId, key: p.key.base64EncodedString(), extName: p.extName,
                browser: p.browser, extensionId: p.extensionId,
                verifiedBrowser: p.verifiedBrowser.isEmpty ? nil : p.verifiedBrowser,
                createdAt: p.createdAt, lastUsed: p.lastUsed))
        write(list)
        if p.verifiedBrowser.isEmpty { unblock(p.extensionId) }
    }

    func touch(_ id: String, at: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        var list = read()
        guard let i = list.firstIndex(where: { $0.pairingId == id }),
            at >= list[i].lastUsed + Self.touchInterval
        else { return }
        list[i].lastUsed = at
        write(list)
    }

    func remove(_ id: String) {
        lock.lock()
        defer { lock.unlock() }
        let list = read()
        let kept = list.filter { $0.pairingId != id }
        if kept.count != list.count { write(kept) }
    }

    /// The user forgot this pairing: remove it and block its extension id from pairing itself
    /// back without a code. The extension id, or nil when the pairing was unknown.
    @discardableResult
    func forget(_ id: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        let list = read()
        guard let gone = list.first(where: { $0.pairingId == id }) else { return nil }
        write(list.filter { $0.pairingId != id })
        var blocked = readBlocked()
        if !blocked.contains(gone.extensionId) {
            blocked.append(gone.extensionId)
            writeBlocked(blocked)
        }
        return gone.extensionId
    }

    func blockedAuto() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return readBlocked()
    }

    /// "Autoriser de nouveau".
    func allowAuto(_ extensionId: String) {
        lock.lock()
        defer { lock.unlock() }
        unblock(extensionId)
    }

    /// Caller holds the lock.
    private func unblock(_ extensionId: String) {
        let blocked = readBlocked()
        let kept = blocked.filter { $0 != extensionId }
        if kept.count != blocked.count { writeBlocked(kept) }
    }

    private func readBlocked() -> [String] {
        guard let data = try? keychain.read(Self.blockedKey) else { return [] }
        return (try? JSONDecoder().decode([String].self, from: data)) ?? []
    }

    private func writeBlocked(_ list: [String]) {
        guard let data = try? JSONEncoder().encode(list) else { return }
        try? keychain.write(Self.blockedKey, data)
    }
}
