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
        let publicKey: Data
        do {
            publicKey = try loadOrCreateKey()
        } catch WatchKeyStoreError.passcodeRequired {
            Self.log.notice("watch passcode required")
            close(to: .needsPasscode)
            return
        } catch {
            Self.log.error("watch key unavailable")
            return
        }
        if state == .needsPasscode { state = .closed }
        transport.sendQueued(.watchKey(publicKey))
        activate()
    }

    /// Foreground: reads the key and the file and opens the vault.
    public func activate() {
        isActive = true
        guard state != .needsPasscode else { return }
        guard let sealed = try? Data(contentsOf: payloadURL) else {
            close(to: .waitingForPhone)
            return
        }
        guard let secret = try? keys.loadSecret() else {
            Self.log.error("watch key unreadable")
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
        // Keychain unreadable (watch locked) or no key yet: not the payload's fault, no refresh.
        guard let secret = try? keys.loadSecret() else {
            Self.log.notice("watch payload ignored: key unavailable")
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
        guard opened.generation() > keys.loadGeneration() else {
            Self.log.error("watch payload refused: replayed generation")
            requestRefresh()
            return
        }
        do {
            try FileManager.default.createDirectory(
                at: payloadURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try sealed.write(to: payloadURL, options: [.atomic, .completeFileProtection])
            try keys.saveGeneration(opened.generation())
        } catch {
            Self.log.error("watch payload could not be stored")
            return
        }
        refreshPending = false
        if isActive { open(opened) }
    }

    private func wipe() {
        try? FileManager.default.removeItem(at: payloadURL)
        do {
            try keys.deleteAll()
        } catch {
            Self.log.error("watch keys could not be deleted")
        }
        close(to: .closed)
        start()
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
