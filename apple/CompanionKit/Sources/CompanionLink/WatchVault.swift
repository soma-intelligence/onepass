import Foundation
import Observation
import OnePassCore
import os

public enum WatchVaultState: Equatable, Sendable {
    /// No passcode on the watch: no key can be created.
    case needsPasscode
    /// Key sent, no payload yet.
    case waitingForPhone
    case ready
    /// The app left the foreground: the vault is released.
    case closed
}

/// What the watch screens read (a fake in previews).
@MainActor
public protocol WatchEntriesModel: AnyObject, Observable {
    var entries: [FfiCompanionEntry] { get }
    var state: WatchVaultState { get }
    func code(for itemID: String, at date: Date) -> FfiTotpCode?
}

/// Watch side of the link. Owns the key pair, stores the sealed payload in a complete-protection
/// file and keeps the opened `CompanionVault` (the only holder of TOTP seeds, in Rust) only
/// between `activate()` and `deactivate()`.
@MainActor
@Observable
public final class WatchVault: WatchEntriesModel {
    public private(set) var entries: [FfiCompanionEntry] = []
    public private(set) var state: WatchVaultState = .closed

    @ObservationIgnored private let transport: any CompanionTransport
    @ObservationIgnored private let keys: any WatchKeyStore
    @ObservationIgnored private let payloadURL: URL
    @ObservationIgnored private var vault: CompanionVault?
    @ObservationIgnored private var isActive = false
    @ObservationIgnored private var transportStarted = false
    /// A refresh was requested and no payload was accepted since: do not ask again, so a phone
    /// stuck on a bad key cannot ping-pong with the watch.
    @ObservationIgnored private var refreshPending = false
    /// A payload arrived while the keychain was unreadable (watch locked) and was dropped:
    /// `activate()` asks for a fresh one once the key reads again. Mirrored by an empty marker
    /// file next to the payload (no secret in it) so it survives a relaunch.
    private var missedPayload: Bool {
        get { FileManager.default.fileExists(atPath: missedURL.path) }
        set {
            if newValue {
                try? FileManager.default.createDirectory(
                    at: missedURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                FileManager.default.createFile(atPath: missedURL.path, contents: Data())
            } else {
                try? FileManager.default.removeItem(at: missedURL)
            }
        }
    }
    private var missedURL: URL { payloadURL.appendingPathExtension("missed") }
    /// A wipe was received but the keys could not be deleted: `start()` finishes it before
    /// loading or resending any key. An empty marker file (no secret), like `missedPayload`.
    private var pendingWipe: Bool {
        get { FileManager.default.fileExists(atPath: wipeURL.path) }
        set {
            if newValue {
                try? FileManager.default.createDirectory(
                    at: wipeURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                FileManager.default.createFile(atPath: wipeURL.path, contents: Data())
            } else {
                try? FileManager.default.removeItem(at: wipeURL)
            }
        }
    }
    private var wipeURL: URL { payloadURL.appendingPathExtension("wipe") }

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "companion")

    public init(transport: any CompanionTransport, keys: any WatchKeyStore, payloadURL: URL) {
        self.transport = transport
        self.keys = keys
        self.payloadURL = payloadURL
    }

    /// Loads (or creates) the key pair, sends the public key to the iPhone and opens the stored
    /// payload.
    public func start() {
        if !transportStarted {
            transportStarted = true
            transport.onMessage = { [weak self] message in self?.receive(message) }
            transport.activate()
        }
        refreshPending = false
        if pendingWipe {
            guard finishWipe() else {
                close(to: .closed)
                return
            }
        }
        let publicKey: Data
        do {
            publicKey = try loadOrCreateKey()
        } catch WatchKeyStoreError.passcodeRequired {
            Self.log.notice("watch passcode required")
            close(to: .needsPasscode)
            return
        } catch {
            // Keychain unreadable (watch locked): the next start() retries.
            Self.log.error("watch key unavailable")
            close(to: .closed)
            return
        }
        if state == .needsPasscode { state = .closed }
        transport.sendQueued(.watchKey(publicKey))
        activate()
    }

    /// Foreground: reads the key and the file and opens the vault.
    public func activate() {
        isActive = true
        // An unfinished wipe: never open the old payload, finish the wipe and rekey instead.
        if pendingWipe {
            start()
            return
        }
        guard state != .needsPasscode else { return }
        let secret: Data
        do {
            guard let stored = try keys.loadSecret() else {
                close(to: .waitingForPhone)
                return
            }
            secret = stored
        } catch {
            // Locked keychain: not the phone's fault, show the vault as closed.
            Self.log.error("watch key unreadable")
            close(to: .closed)
            return
        }
        if missedPayload { requestRefresh() }
        guard let sealed = try? Data(contentsOf: payloadURL) else {
            close(to: .waitingForPhone)
            return
        }
        do {
            open(try CompanionVault.open(secret: secret, sealed: sealed))
        } catch {
            Self.log.error("stored watch payload unreadable")
            close(to: .waitingForPhone)
            requestRefresh()
        }
    }

    /// Background: releases the vault and the entries.
    public func deactivate() {
        isActive = false
        close(to: state == .needsPasscode ? .needsPasscode : .closed)
    }

    public func code(for itemID: String, at date: Date) -> FfiTotpCode? {
        vault?.totp(itemId: itemID, unixSeconds: UInt64(max(0, date.timeIntervalSince1970)))
    }

    private func receive(_ message: CompanionMessage) {
        switch message {
        case .payload(let sealed): accept(sealed)
        case .wipe: wipe()
        case .watchKey, .refreshRequest: break
        }
    }

    private func accept(_ sealed: Data) {
        // An unfinished wipe: the old key must not open anything.
        guard !pendingWipe else {
            Self.log.notice("watch payload ignored: wipe pending")
            return
        }
        // Keychain unreadable (watch locked): not the payload's fault, so no refresh now (that
        // would loop while locked), but remember the miss for the next activate().
        let secret: Data
        do {
            guard let stored = try keys.loadSecret() else {
                Self.log.notice("watch payload ignored: no key")
                return
            }
            secret = stored
        } catch {
            Self.log.notice("watch payload missed: key unavailable")
            missedPayload = true
            return
        }
        let opened: CompanionVault
        do {
            opened = try CompanionVault.open(secret: secret, sealed: sealed)
        } catch {
            Self.log.error("watch payload refused: unreadable")
            requestRefresh()
            return
        }
        let floor: UInt64
        do {
            floor = try keys.loadGeneration()
        } catch {
            // Without the floor, any replay could pass: refuse everything.
            Self.log.error("watch payload missed: generation unreadable")
            missedPayload = true
            return
        }
        guard opened.generation() > floor else {
            Self.log.error("watch payload refused: replayed generation")
            requestRefresh()
            return
        }
        // Raise the floor first: if the file write then fails, an older payload still cannot
        // come back.
        do {
            try keys.saveGeneration(opened.generation())
        } catch {
            Self.log.error("watch payload missed: generation not saved")
            missedPayload = true
            return
        }
        do {
            try FileManager.default.createDirectory(
                at: payloadURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try sealed.write(to: payloadURL, options: [.atomic, .completeFileProtection])
        } catch {
            Self.log.error("watch payload could not be stored")
            missedPayload = true
            return
        }
        missedPayload = false
        refreshPending = false
        if isActive { open(opened) }
    }

    /// Deletes the keys first: without the secret key the sealed file is unreadable
    /// (crypto-erase), so a failed file removal cannot leave the payload readable. A failed key
    /// deletion leaves the pending-wipe marker, and `start()` retries before using any key.
    private func wipe() {
        close(to: .closed)
        pendingWipe = true
        guard finishWipe() else { return }
        start()
    }

    /// Deletes the keys, then the file (best effort) and the markers. False when the keys could
    /// not be deleted: the marker stays and the old key must not be used or resent.
    private func finishWipe() -> Bool {
        do {
            try keys.deleteAll()
        } catch {
            Self.log.error("watch wipe failed: keys not deleted")
            return false
        }
        try? FileManager.default.removeItem(at: payloadURL)
        missedPayload = false
        pendingWipe = false
        return true
    }

    private func loadOrCreateKey() throws -> Data {
        if let secret = try keys.loadSecret(), !secret.isEmpty,
            let publicKey = try keys.loadPublicKey(), !publicKey.isEmpty
        {
            return publicKey
        }
        let pair = try companionGenerateKey()
        try keys.saveSecret(pair.secret)
        try keys.savePublicKey(pair.public)
        return pair.public
    }

    private func requestRefresh() {
        guard !refreshPending else { return }
        refreshPending = true
        transport.sendQueued(.refreshRequest)
    }

    private func open(_ opened: CompanionVault) {
        vault = opened
        entries = opened.entries()
        state = .ready
    }

    private func close(to newState: WatchVaultState) {
        vault = nil
        entries = []
        state = newState
    }
}
