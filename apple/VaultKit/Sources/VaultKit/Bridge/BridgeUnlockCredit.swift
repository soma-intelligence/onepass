import Foundation

/// One Touch ID for a locked vault and an item marked `reprompt` (owner ruling 2026-11-10): the
/// biometric check that unlocked the vault for a browser also answers the presence check of the fill
/// that follows from the same click.
///
/// A paired extension asks the bridge to unlock for a page; when the vault then opens by biometrics
/// (never by the master password), one credit lives for `lifetime`. It belongs to that paired client
/// and that page's host: only a `reprompt` request from the same pairing, for the same host, takes it
/// and is answered without a second prompt. Another paired browser, another site, or a request that
/// names no host gets the normal prompt and leaves the credit alone. An unlock the user did on their
/// own grants nothing, and a lock clears everything.
public struct BridgeUnlockCredit: Sendable, Equatable {
    /// How long a browser's request waits for its unlock (the extension's minute of polling plus
    /// Touch ID, as `BrowserReturn.window`).
    public static let requestWindow: TimeInterval = BrowserReturn.window
    /// How long the unlock answers for a presence check.
    public static let lifetime: TimeInterval = 10

    private struct Request: Sendable, Equatable {
        let until: Date
        let pairing: String
        /// Normalized; nil when the extension named no page (no credit will come of it).
        let host: String?
    }

    private struct Credit: Sendable, Equatable {
        let until: Date
        let pairing: String
        let host: String
    }

    private var request: Request?
    private var credit: Credit?

    public init() {}

    /// A host as the credit compares it and as a prompt may show it: lowercased, without a trailing
    /// dot, made of letters, digits, dots and hyphens only (an internationalized name comes in its
    /// ASCII form). Anything else is no host.
    public static func host(_ raw: String?) -> String? {
        guard var host = raw?.lowercased() else { return nil }
        if host.hasSuffix(".") { host.removeLast() }
        guard !host.isEmpty, host.utf8.count <= 253,
            host.utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2E || $0 == 0x2D })
        else { return nil }
        return host
    }

    /// The paired client `pairing` asked the bridge to unlock the locked vault, for the page on
    /// `host` when it said. The latest request is the one that counts.
    public mutating func unlockRequested(now: Date, pairing: String, host: String?) {
        request = Request(until: now.addingTimeInterval(Self.requestWindow), pairing: pairing, host: Self.host(host))
    }

    /// The host of the request that waits for its unlock, for the Touch ID reason.
    public func requestedHost(now: Date) -> String? {
        guard let request, now <= request.until else { return nil }
        return request.host
    }

    /// The vault unlocked. `biometric`: by Touch ID (or the watch) on the lock screen, not by the
    /// master password. The request is spent either way; without a host it grants nothing.
    public mutating func unlocked(biometric: Bool, now: Date) {
        defer { request = nil }
        credit = nil
        guard biometric, let request, now <= request.until, let host = request.host, !request.pairing.isEmpty
        else { return }
        credit = Credit(until: now.addingTimeInterval(Self.lifetime), pairing: request.pairing, host: host)
    }

    /// A `reprompt` presence request of the paired client `pairing` for the page on `host`: true
    /// once, while the credit lives, when both are the ones the unlock was asked by and for. A
    /// request that does not match takes nothing.
    public mutating func consume(now: Date, pairing: String, host: String?) -> Bool {
        guard let credit else { return false }
        guard now <= credit.until else {
            self.credit = nil
            return false
        }
        guard let host = Self.host(host), host == credit.host, pairing == credit.pairing else { return false }
        self.credit = nil
        return true
    }

    /// The vault locked.
    public mutating func clear() {
        request = nil
        credit = nil
    }
}
