import Foundation
import OnePassCore
import os

/// The core calls the iPhone side of the remote approval needs (agent-ready spec 5 and 6).
/// `Session` is the real one.
public protocol RemoteResponderSession: Sendable {
    func thisDeviceId() -> String?
    func approvers() throws -> [FfiApprover]
    func openRemoteRequest(keys: FfiApproverKeys, blob: Data) throws -> FfiOpenedRequest
    func sealRemoteResponse(
        keys: FfiApproverKeys, requestBlob: Data, decision: FfiRemoteDecision, unlockKey: Data?
    ) throws -> Data
    func acceptEnrollment(keys: FfiApproverKeys, requestBlob: Data) throws -> Data
    func sealRemoteNotice(keys: FfiApproverKeys, mac: String, kind: FfiNoticeKind) throws -> FfiSealedRequest
}

extension Session: RemoteResponderSession {}

/// A request from a Mac the core verified (signature, recipient, expiry, replay): what the phone
/// shows, never a secret (`K_r` of a pairing stays in the core until `acceptEnrollment`).
public struct OpenedRequest: Sendable, Identifiable {
    /// The record name in the transport.
    public let id: String
    public let requestId: Data
    /// The Mac's device id and its name in the device list.
    public let mac: String
    public let macName: String
    public let kind: FfiRemoteKind
    public let body: FfiRequestBody
    public let expiresAt: Date
    /// The phone answers until then, on its own clock: one request lifetime after it arrived, and
    /// never past the expiry plus the clock tolerance.
    public let deadline: Date
    let blob: Data

    /// The first of the two steps (spec 6.2): unlock the Mac for the agents.
    public var isUnlock: Bool { kind == .unlock || kind == .approveAndUnlock }
    /// The Mac sends `K_r` (spec 6.1).
    public var isPairing: Bool { kind == .pair }
    /// "Autoriser 5 min" is offered.
    public var mayGrantMinutes: Bool { body.rememberAllowed && !isPairing }
}

/// Why an answer did not leave the phone.
public enum RemoteResponderError: Error, Equatable, Sendable {
    /// Face ID refused, cancelled or unavailable: nothing was sent.
    case presenceRequired
    /// The request expired (or was answered already).
    case expired
    /// Not a request this phone holds.
    case unknownRequest
    /// No usable `K_r` for that Mac (never enrolled, or invalidated by a Face ID change): enroll
    /// again from the Mac.
    case notEnrolled
    /// The biometric set changed (a face or appearance added, Face ID reset): the Face ID gate must
    /// be armed again from Réglages > Agents.
    case faceIDChanged
    /// That answer does not fit that request ("5 min" not allowed, a pairing answered as a request).
    case notAllowed
    /// A request the phone's clock alone calls expired, or dates in its future: its clock is likely
    /// wrong.
    case clockSkew
    /// CloudKit unreachable, or the core refused to seal (this phone is not an approver).
    case unavailable

    public var message: String {
        switch self {
        case .presenceRequired:
            String(localized: "Face ID est nécessaire pour répondre.", bundle: VaultKitStrings.bundle)
        case .expired:
            String(localized: "Cette demande a expiré.", bundle: VaultKitStrings.bundle)
        case .unknownRequest:
            String(localized: "Cette demande n'est plus disponible.", bundle: VaultKitStrings.bundle)
        case .notEnrolled:
            String(localized: "Le déverrouillage à distance de ce Mac n'est pas actif sur cet iPhone : réactive-le depuis le Mac.", bundle: VaultKitStrings.bundle)
        case .faceIDChanged:
            String(localized: "Face ID a changé : réactive Face ID dans Réglages > Agents.", bundle: VaultKitStrings.bundle)
        case .notAllowed:
            String(localized: "Cette réponse n'est pas permise pour cette demande.", bundle: VaultKitStrings.bundle)
        case .clockSkew:
            String(localized: "Vérifie l'heure de ton iPhone : elle ne correspond pas à celle de ton Mac.", bundle: VaultKitStrings.bundle)
        case .unavailable:
            String(localized: "Le Mac est injoignable pour l'instant. Réessaie.", bundle: VaultKitStrings.bundle)
        }
    }
}

/// iPhone side of the remote approval (agent-ready spec 5 and 6): reads the phone's messages through
/// one `RemoteMailbox` (the only reader of this device's records), keeps the requests the core
/// opened, and answers them after Face ID. Every answer, a refusal included, needs Face ID of the
/// current biometric set first; a Face ID refused sends nothing. An unlock approval reads `K_r` of
/// that Mac behind that same Face ID and seals it to the request's ephemeral key.
///
/// A request the phone cannot open stays for its expiry (the mailbox erases it then). The phone's
/// clock is judged against two others (spec Review Focus 1): the Mac's (the signed dates) and the
/// server's (the record's creation time). A request dated beyond the request lifetime plus the
/// clock tolerance in the phone's future means the phone is late; a request the phone calls
/// expired by more than the tolerance although the server stored it when the Mac says it was made
/// means the phone is ahead (or the record was left behind, which the launch purge and the Mac's
/// withdrawal clear). Either way `clockLooksWrong` turns on and the record goes.
public actor RemoteResponder {
    /// A request lives 60 s on the Mac (spec 5.1).
    public static let requestLifetime: TimeInterval = 60
    /// The phone's clock may be 120 s off (spec 5.1).
    public static let clockTolerance: TimeInterval = 120

    /// The last request the phone could not open disagreed with its clock by more than the tolerance.
    public private(set) var clockLooksWrong = false
    /// The Face ID gate was invalidated by a change of the biometric set: `reArmFaceID()`.
    public private(set) var faceIDNeedsReset = false

    private let channel: any RemoteChannel
    private let session: any RemoteResponderSession
    private let keys: FfiApproverKeys
    private let presence: any PresenceChecker
    private let keyring: any RemoteUnlockKeyring
    private let now: @Sendable () -> Date
    private var mailbox: RemoteMailbox?
    private var subscription: UUID?
    private var requests: [String: OpenedRequest] = [:]
    private var onChange: (@Sendable () -> Void)?
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "remote")

    /// `keys`: this phone's approval keys (`ApproverKeyStore`). `presence`: Face ID of the current
    /// set (`CurrentBiometryPresence` in the app). `keyring`: where `K_r` of each Mac lives.
    public init(
        channel: any RemoteChannel, session: any RemoteResponderSession, keys: FfiApproverKeys,
        presence: any PresenceChecker, keyring: any RemoteUnlockKeyring = SystemRemoteUnlockKeyring(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.channel = channel
        self.session = session
        self.keys = keys
        self.presence = presence
        self.keyring = keyring
        self.now = now
    }

    deinit {
        if let mailbox, let subscription {
            Task { await mailbox.unregister(subscription) }
        }
    }

    /// Told after each change of `pending()` or `clockLooksWrong` (off the main actor).
    public func setOnChange(_ handler: (@Sendable () -> Void)?) {
        onChange = handler
    }

    // MARK: - Reading

    /// Starts reading this phone's messages (the vault is open). Idempotent.
    public func start() async {
        guard subscription == nil, let me = session.thisDeviceId() else { return }
        let box = mailbox ?? RemoteMailbox(channel: channel, device: me, now: now)
        mailbox = box
        subscription = await box.register(.approval) { [weak self] message in
            await self?.receive(message) ?? false
        }
    }

    /// Stops reading and forgets the requests (the vault locked).
    public func stop() async {
        if let mailbox, let subscription { await mailbox.unregister(subscription) }
        subscription = nil
        requests = [:]
        changed()
    }

    /// Erases the records that expired (at launch, spec 5.2).
    public func purgeExpired() async {
        await channel.purgeExpired(now: now())
    }

    /// The requests that may still be answered, oldest first (expired ones are hidden).
    public func pending() -> [OpenedRequest] {
        let current = now()
        return requests.values.filter { $0.deadline > current }.sorted { $0.expiresAt < $1.expiresAt }
    }

    private func receive(_ message: RemoteMessage) async -> Bool {
        let current = now()
        if current.timeIntervalSince(message.expiresAt) > Self.clockTolerance {
            let made = message.expiresAt.addingTimeInterval(-Self.requestLifetime)
            if let stored = message.sentAt, abs(stored.timeIntervalSince(made)) <= Self.clockTolerance {
                // The server stored it when the Mac says it was made: only this phone's clock calls
                // it expired, so it runs ahead.
                Self.log.notice("remote request expired on this phone's clock only")
                clockLooksWrong = true
                changed()
                return true
            }
            // Expired on every clock: left to the mailbox, which erases it.
            return false
        }
        if message.expiresAt.timeIntervalSince(current) > Self.requestLifetime + Self.clockTolerance {
            // No valid request is dated that far ahead: this phone's clock is late. Nothing here
            // will ever open it.
            Self.log.notice("remote request dated in the future of this phone")
            clockLooksWrong = true
            changed()
            return true
        }
        let session = self.session
        let keys = self.keys
        let blob = message.blob
        let opened: FfiOpenedRequest
        do {
            opened = try await CoreThread.run { try session.openRemoteRequest(keys: keys, blob: blob) }
        } catch OnePassError.Integrity(let kind) where kind == "remote_expired" {
            // The clear expiry disagrees with the signed one: not a request of a Mac.
            return true
        } catch {
            // Forged, replayed, for a Mac not in the list: left until it expires.
            Self.log.notice("remote request refused")
            return false
        }
        guard [.approve, .unlock, .approveAndUnlock, .pair].contains(opened.kind) else { return true }
        // The expired ones held so far go (an answer to them would be refused anyway).
        requests = requests.filter { $0.value.deadline > current }
        let expiresAt = Date(timeIntervalSince1970: TimeInterval(opened.expiresAt))
        let deadline = min(
            current.addingTimeInterval(Self.requestLifetime), expiresAt.addingTimeInterval(Self.clockTolerance))
        requests[message.id] = OpenedRequest(
            id: message.id, requestId: opened.requestId, mac: opened.from, macName: opened.fromName,
            kind: opened.kind, body: opened.body, expiresAt: expiresAt, deadline: deadline, blob: message.blob)
        clockLooksWrong = false
        changed()
        return true
    }

    // MARK: - Answers

    static var answerPrompt: String {
        String(localized: "Répondre à la demande de l'agent", bundle: VaultKitStrings.bundle)
    }

    static var enrollPrompt: String {
        String(localized: "Activer le déverrouillage à distance de ce Mac", bundle: VaultKitStrings.bundle)
    }

    /// Answers a request after Face ID. For an unlock approval, `K_r` of that Mac is read behind
    /// Face ID of the current set (that read is the presence check) and sealed to the request.
    public func answer(_ id: String, decision: FfiRemoteDecision) async throws {
        let request = try live(id)
        guard !request.isPairing else { throw RemoteResponderError.notAllowed }
        if decision == .grant5m && !request.mayGrantMinutes { throw RemoteResponderError.notAllowed }

        var unlockKey: Data?
        if request.isUnlock && decision != .denied {
            if let enrolled = try? keyring.macs(), !enrolled.contains(request.mac) {
                throw RemoteResponderError.notEnrolled
            }
            switch await keyring.read(for: request.mac, prompt: Self.answerPrompt) {
            case .found(let key):
                unlockKey = key
            case .refused:
                throw RemoteResponderError.presenceRequired
            case .missing:
                // Invalidated by a Face ID change (or gone): only a new enrollment from the Mac
                // brings it back. The dead entry goes, so the settings say so.
                try? keyring.delete(for: request.mac)
                throw RemoteResponderError.notEnrolled
            }
        } else {
            try await confirmPresence(Self.answerPrompt)
        }
        defer {
            // Best effort: `Data` may hold other copies the core call released by now.
            if let count = unlockKey?.count { unlockKey?.resetBytes(in: 0..<count) }
        }
        // Face ID may have taken a while.
        _ = try live(id)

        let session = self.session
        let keys = self.keys
        let blob = request.blob
        let sealedKey = unlockKey
        let response: Data
        do {
            response = try await CoreThread.run {
                try session.sealRemoteResponse(keys: keys, requestBlob: blob, decision: decision, unlockKey: sealedKey)
            }
        } catch OnePassError.Integrity(let kind) where kind == "remote_expired" {
            drop(id)
            throw RemoteResponderError.expired
        } catch {
            Self.log.error("remote answer not sealed")
            throw RemoteResponderError.unavailable
        }
        do {
            try await channel.post(RemoteMessage(
                id: "response-" + RemoteApprover.hex(request.requestId), to: request.mac, blob: response,
                expiresAt: request.expiresAt.addingTimeInterval(Self.clockTolerance)))
        } catch {
            // Kept: the owner may try again while it lasts.
            throw RemoteResponderError.unavailable
        }
        drop(id)
    }

    /// Takes `K_r` of a pairing after Face ID and keeps it in this phone's keychain (this device
    /// only, Face ID of the current set). Nothing is sent back: the Mac already holds `C`.
    public func acceptEnrollment(_ id: String) async throws {
        let request = try live(id)
        guard request.isPairing else { throw RemoteResponderError.notAllowed }
        try await confirmPresence(Self.enrollPrompt)
        _ = try live(id)
        let session = self.session
        let keys = self.keys
        let blob = request.blob
        var key: Data
        do {
            key = try await CoreThread.run { try session.acceptEnrollment(keys: keys, requestBlob: blob) }
        } catch {
            drop(id)
            throw RemoteResponderError.expired
        }
        defer { key.resetBytes(in: 0..<key.count) }
        do {
            try keyring.save(key, for: request.mac)
        } catch {
            Self.log.error("remote unlock key not stored")
            throw RemoteResponderError.unavailable
        }
        drop(id)
    }

    /// Face ID of the current set. A gate that tells a changed biometric set apart reports it as
    /// `faceIDChanged` (asking again cannot help), anything else as `presenceRequired`.
    private func confirmPresence(_ prompt: String) async throws {
        if let gate = presence as? any FaceIDGate {
            switch await gate.check(prompt: prompt) {
            case .confirmed:
                return
            case .refused:
                throw RemoteResponderError.presenceRequired
            case .invalidated:
                faceIDNeedsReset = true
                changed()
                throw RemoteResponderError.faceIDChanged
            }
        }
        guard await presence.confirmWithBiometrics(prompt: prompt) else {
            throw RemoteResponderError.presenceRequired
        }
    }

    static var rearmPrompt: String {
        String(localized: "Réactiver Face ID pour les demandes des agents", bundle: VaultKitStrings.bundle)
    }

    /// After a Face ID change: the gate is written again for the current biometric set, then read
    /// once (a Face ID of that set). The responder only exists while the vault is open. A refused
    /// Face ID leaves no gate behind.
    public func reArmFaceID() async throws {
        guard let gate = presence as? any FaceIDGate else { return }
        do {
            try gate.arm()
        } catch {
            Self.log.error("face id gate not written")
            throw RemoteResponderError.unavailable
        }
        guard await gate.check(prompt: Self.rearmPrompt) == .confirmed else {
            try? gate.disarm()
            throw RemoteResponderError.presenceRequired
        }
        faceIDNeedsReset = false
        changed()
    }

    /// Drops a request without answering (a pairing the owner refuses: nothing is sent).
    public func dismiss(_ id: String) {
        drop(id)
    }

    private func live(_ id: String) throws -> OpenedRequest {
        guard let request = requests[id] else { throw RemoteResponderError.unknownRequest }
        guard now() < request.deadline else {
            drop(id)
            throw RemoteResponderError.expired
        }
        return request
    }

    private func drop(_ id: String) {
        guard requests.removeValue(forKey: id) != nil else { return }
        changed()
    }

    private func changed() {
        onChange?()
    }

    // MARK: - Remote unlock

    /// The Macs whose `K_r` this phone holds.
    public func enrolledMacs() -> [String] {
        ((try? keyring.macs()) ?? []).sorted()
    }

    /// "Oublier le déverrouillage à distance" (spec 6.4): `K_r` is erased here, then the Mac is told
    /// to erase `C`. A lost notice reopens nothing (half alone opens nothing).
    ///
    /// Ruling: `Lock` and `ForgetUnlock` go without Face ID. They only take rights away (end a
    /// window, drop the pairing) and need the vault open on this phone already.
    public func forget(mac: String) async throws {
        do {
            try keyring.delete(for: mac)
        } catch {
            Self.log.error("remote unlock key not erased")
            throw RemoteResponderError.unavailable
        }
        try await send(.forgetUnlock, to: mac)
    }

    /// "Verrouiller maintenant" (spec 6.3): the Mac ends its agents-only window.
    public func lockNow(mac: String) async throws {
        try await send(.lock, to: mac)
    }

    /// Erases `K_r` of every Mac that is no longer an active Mac approver (revoked in the device
    /// list, or its approval keys retired). A list that cannot be read erases nothing.
    public func dropRevokedMacs() async {
        guard let stored = try? keyring.macs(), !stored.isEmpty else { return }
        let session = self.session
        guard let list = try? await CoreThread.run({ try session.approvers() }) else { return }
        let active = Set(list.filter { $0.role == .mac }.map(\.deviceId))
        for mac in stored where !active.contains(mac) {
            do {
                try keyring.delete(for: mac)
            } catch {
                Self.log.error("remote unlock key of a revoked Mac not erased")
            }
        }
    }

    private func send(_ kind: FfiNoticeKind, to mac: String) async throws {
        let session = self.session
        let keys = self.keys
        let sealed: FfiSealedRequest
        do {
            sealed = try await CoreThread.run { try session.sealRemoteNotice(keys: keys, mac: mac, kind: kind) }
        } catch {
            Self.log.error("remote notice not sealed")
            throw RemoteResponderError.unavailable
        }
        do {
            try await channel.post(RemoteMessage(
                id: "notice-" + RemoteApprover.hex(sealed.requestId), to: sealed.to, blob: sealed.blob,
                expiresAt: Date(timeIntervalSince1970: TimeInterval(sealed.expiresAt))))
        } catch {
            throw RemoteResponderError.unavailable
        }
    }
}
