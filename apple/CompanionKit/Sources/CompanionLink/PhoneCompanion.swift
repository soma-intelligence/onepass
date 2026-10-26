import Foundation
import Observation
import os

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
    }

    /// The "Apple Watch" setting (on by default).
    public var isEnabled: Bool {
        didSet { defaults.set(isEnabled, forKey: Key.enabled) }
    }
    public private(set) var watchPublicKey: Data?
    public private(set) var generation: UInt64
    public private(set) var lastSent: Date?
    public var status: CompanionStatus { transport.status }

    @ObservationIgnored private let transport: any CompanionTransport
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let seal: @MainActor (Data, UInt64) async throws -> Data
    /// The last scheduled send; each new one waits for it.
    @ObservationIgnored private var inFlight: Task<Void, Never>?

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "companion")

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

    /// Asks the watch to forget everything and rekey; the phone forgets the old key first, so
    /// the new one is learned when the watch sends it.
    public func wipeWatch() {
        watchPublicKey = nil
        defaults.removeObject(forKey: Key.watchKey)
        do {
            try transport.sendLatest(.wipe)
        } catch {
            Self.log.error("watch wipe could not be sent")
        }
    }

    /// Waits for the sends scheduled so far (tests).
    func settle() async {
        await inFlight?.value
    }

    private func receive(_ message: CompanionMessage) {
        switch message {
        case .watchKey(let key):
            guard key != watchPublicKey else { return }
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
            return
        }
        generation = next
        lastSent = now
        defaults.set(NSNumber(value: next), forKey: Key.generation)
        defaults.set(now, forKey: Key.lastSent)
    }
}
