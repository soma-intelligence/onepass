import CryptoKit
import Foundation
import Observation
import os

/// A failure the settings page shows ("Dernier envoi" area). Cleared by the next success.
public enum CompanionIssue: Equatable, Sendable {
    /// A sealed payload could not be handed to the transport.
    case sendFailed
    /// The wipe could not be handed to the transport: the watch may still hold its data.
    case wipeFailed
}

/// iPhone side of the watch link. Keeps the watch public key (not a secret), the payload
/// generation and the last send date in `defaults`, and pushes a freshly sealed payload with
/// `sendLatest` whenever the vault changes. Sends are serialized: one at a time, in call order.
@MainActor
@Observable
public final class PhoneCompanion {
    private enum Key {
        static let enabled = "companion.enabled"
        static let watchKey = "companion.watchKey"
        static let generation = "companion.generation"
        static let lastSent = "companion.lastSent"
        static let wipedKey = "companion.wipedKey"
    }

    /// The "Apple Watch" setting (on by default).
    public var isEnabled: Bool {
        didSet { defaults.set(isEnabled, forKey: Key.enabled) }
    }
    public private(set) var watchPublicKey: Data?
    public private(set) var generation: UInt64
    public private(set) var lastSent: Date?
    public private(set) var lastError: CompanionIssue?
    public var status: CompanionStatus { transport.status }

    @ObservationIgnored private let transport: any CompanionTransport
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let seal: @MainActor (Data, UInt64) async throws -> Data
    /// The last scheduled send; each new one waits for it.
    @ObservationIgnored private var inFlight: Task<Void, Never>?

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "companion")
    /// Hybrid ML-KEM-1024 + X25519 public key (`companionGenerateKey().public`).
    static let watchKeyLength = 1600

    /// `seal(watchPublicKey, generation)` returns the sealed payload (`Session.companionPayload`);
    /// it throws while the vault is locked.
    public init(
        transport: any CompanionTransport, defaults: UserDefaults,
        seal: @escaping @MainActor (Data, UInt64) async throws -> Data
    ) {
        self.transport = transport
        self.defaults = defaults
        self.seal = seal
        isEnabled = defaults.object(forKey: Key.enabled) as? Bool ?? true
        watchPublicKey = defaults.data(forKey: Key.watchKey)
        generation = (defaults.object(forKey: Key.generation) as? NSNumber)?.uint64Value ?? 0
        lastSent = defaults.object(forKey: Key.lastSent) as? Date
    }

    public func start() {
        transport.onMessage = { [weak self] message in self?.receive(message) }
        transport.activate()
    }

    /// Seals and sends the current vault. Nothing happens while the setting is off, before the
    /// watch sent its key or when the watch cannot be reached. A sealing or sending failure
    /// sends nothing and keeps the generation: the next change retries.
    public func vaultChanged() async {
        await scheduleSend().value
    }

    /// Asks the watch to forget everything and rekey. The phone forgets the key and remembers
    /// its SHA-256: a stale copy of that key arriving later (queued before the wipe was
    /// processed, or resent by a watch that never got the wipe) is ignored, so no payload can
    /// replace the wipe. Only a different key (the rekeyed watch) resumes sending.
    /// The wipe goes through both channels: the latest-only context, and the queue, which a
    /// later context cannot replace. A failure is published in `lastError`.
    /// The setting is turned off too: otherwise the unlocked phone would seal the same items for
    /// the rekeyed watch seconds later. Turning it back on sends again.
    public func wipeWatch() {
        isEnabled = false
        if let key = watchPublicKey {
            defaults.set(Self.fingerprint(key), forKey: Key.wipedKey)
        }
        watchPublicKey = nil
        defaults.removeObject(forKey: Key.watchKey)
        do {
            try transport.sendLatest(.wipe)
            lastError = nil
        } catch {
            Self.log.error("watch wipe could not be sent")
            lastError = .wipeFailed
        }
        transport.sendQueued(.wipe)
    }

    /// Waits for the sends scheduled so far (tests).
    func settle() async {
        await inFlight?.value
    }

    private func receive(_ message: CompanionMessage) {
        switch message {
        case .watchKey(let key):
            guard key != watchPublicKey else { return }
            // A malformed key would make every later seal fail: never store it.
            guard key.count == Self.watchKeyLength else {
                Self.log.error("watch key refused: wrong length")
                return
            }
            if defaults.data(forKey: Key.wipedKey) == Self.fingerprint(key) {
                Self.log.notice("wiped watch key ignored")
                return
            }
            defaults.removeObject(forKey: Key.wipedKey)
            watchPublicKey = key
            defaults.set(key, forKey: Key.watchKey)
            scheduleSend()
        case .refreshRequest:
            scheduleSend()
        case .payload, .wipe:
            break
        }
    }

    @discardableResult
    private func scheduleSend() -> Task<Void, Never> {
        let previous = inFlight
        let task = Task { @MainActor [weak self] in
            await previous?.value
            await self?.sendNow()
        }
        inFlight = task
        return task
    }

    private func sendNow() async {
        guard isEnabled, let key = watchPublicKey, transport.status == .ready else { return }
        // Milliseconds since 1970 as a floor: a phone that lost its counter still goes above
        // the last generation the watch accepted.
        let now = Date()
        let next = max(generation &+ 1, UInt64(max(0, now.timeIntervalSince1970 * 1000)))
        let sealed: Data
        do {
            sealed = try await seal(key, next)
        } catch {
            Self.log.notice("watch payload not sealed (vault locked or core error)")
            return
        }
        // The key may have changed (or been wiped) while sealing.
        guard isEnabled, key == watchPublicKey else { return }
        do {
            try transport.sendLatest(.payload(sealed))
        } catch {
            Self.log.error("watch payload could not be sent")
            lastError = .sendFailed
            return
        }
        generation = next
        lastSent = now
        lastError = nil
        defaults.set(NSNumber(value: next), forKey: Key.generation)
        defaults.set(now, forKey: Key.lastSent)
    }

    private static func fingerprint(_ key: Data) -> Data {
        Data(SHA256.hash(data: key))
    }
}
