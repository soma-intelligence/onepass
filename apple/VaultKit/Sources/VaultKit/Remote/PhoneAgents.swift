import Foundation
import Observation
import OnePassCore
import os

/// What the iPhone app shows of the agents (agent-ready spec 7, Réglages > Agents and the request
/// screen): the requests a `RemoteResponder` holds while the vault is open, the Macs of the
/// account, the local journal. iPhone only: on the Mac, `RemoteUnlockCoordinator` owns the vault's
/// device hook.
@MainActor
@Observable
public final class PhoneAgents {
    public struct Mac: Identifiable, Equatable, Sendable {
        public let id: String
        public let name: String
        /// This phone holds `K_r` for it.
        public let unlockEnrolled: Bool
        /// End of the agents-only window this phone asked for, as far as it knows: the Mac does not
        /// confirm it opened (it may refuse, or the window may already have ended), so the settings
        /// say "requested".
        public let windowEndsAt: Date?
    }

    /// One answer given on this phone (no secret: who asked what, and the answer).
    public struct LogLine: Identifiable, Codable, Equatable, Sendable {
        public var id: UUID
        public var date: Date
        public var mac: String
        public var client: String
        public var action: String
        public var decision: String
    }

    /// The journal keeps the last 20 answers (spec 7).
    public static let logLimit = 20

    public private(set) var requests: [OpenedRequest] = []
    public private(set) var clockLooksWrong = false
    /// Face ID changed on this iPhone: answers fail until "Réactiver Face ID".
    public private(set) var faceIDNeedsReset = false
    public private(set) var macs: [Mac] = []
    /// This phone is a phone approver of the account (its approval keys are in the signed list).
    public private(set) var isEnabled = false
    public private(set) var log: [LogLine] = []
    /// Set when a request arrives or a notification is tapped; the app shows the request screen.
    public var showRequests = false
    /// A remote transport exists (CloudKit build).
    public var isAvailable: Bool { channel != nil }

    @ObservationIgnored private let vault: VaultSession
    @ObservationIgnored private let channel: (any RemoteChannel)?
    @ObservationIgnored private let approverKeys: ApproverKeyStore
    @ObservationIgnored private let keyring: SystemRemoteUnlockKeyring
    @ObservationIgnored private let presence: any PresenceChecker
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let sharedDefaults: UserDefaults?
    @ObservationIgnored private var responder: RemoteResponder?
    @ObservationIgnored private var windows: [String: Date] = [:]
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "remote")
    static let logKey = "onepass.remote.log"
    /// Read by the Notification Service Extension: the names of the account's Macs.
    public static let macNamesKey = "onepass.remote.macNames"

    /// `sharedDefaults`: the App Group defaults the Notification Service Extension reads.
    public init(
        vault: VaultSession, channel: (any RemoteChannel)?, approverKeys: ApproverKeyStore = ApproverKeyStore(),
        keyring: SystemRemoteUnlockKeyring = SystemRemoteUnlockKeyring(),
        presence: (any PresenceChecker)? = nil, defaults: UserDefaults = .standard, sharedDefaults: UserDefaults? = nil
    ) {
        self.vault = vault
        self.channel = channel
        self.approverKeys = approverKeys
        self.keyring = keyring
        self.presence = presence ?? CurrentBiometryPresence(keyring: keyring)
        self.defaults = defaults
        self.sharedDefaults = sharedDefaults
        if let data = defaults.data(forKey: Self.logKey),
            let lines = try? JSONDecoder().decode([LogLine].self, from: data)
        {
            log = lines
        }
        vault.devicesRefreshed = { [weak self] _ in
            Task { await self?.dropRevokedAndRefresh() }
        }
    }

    // MARK: - Lifecycle

    /// At launch: the records that expired while the app was gone are erased (spec 5.2).
    public func purgeExpired() async {
        await channel?.purgeExpired(now: Date())
    }

    /// The vault opened or locked: the phone reads its requests only while it is open.
    public func sessionChanged() async {
        guard vault.state == .unlocked, let core = vault.coreSession, let channel else {
            await stopReading()
            return
        }
        guard responder == nil else { return }
        let approverKeys = self.approverKeys
        guard let keys = await Task.detached(operation: { try? approverKeys.load() }).value else {
            await refresh()
            return
        }
        // The vault may have locked (or another call started a responder) during the read.
        guard vault.state == .unlocked, vault.coreSession === core, responder == nil else { return }
        let responder = RemoteResponder(
            channel: channel, session: core, keys: keys, presence: presence, keyring: keyring)
        self.responder = responder
        await responder.setOnChange { [weak self] in
            Task { @MainActor in await self?.pull() }
        }
        await responder.start()
        await dropRevokedAndRefresh()
    }

    private func stopReading() async {
        let old = responder
        responder = nil
        requests = []
        await old?.stop()
    }

    /// A notification of a request was tapped.
    public func notificationTapped() {
        showRequests = true
    }

    private func pull() async {
        guard let responder else { return }
        let before = Set(requests.map(\.id))
        requests = await responder.pending()
        clockLooksWrong = await responder.clockLooksWrong
        faceIDNeedsReset = await responder.faceIDNeedsReset
        if requests.contains(where: { !before.contains($0.id) }) { showRequests = true }
    }

    /// Hides the requests that expired since the last change (the request screen ticks).
    public func expireStale() async {
        guard let responder else { return }
        requests = await responder.pending()
        clockLooksWrong = await responder.clockLooksWrong
    }

    // MARK: - Settings

    /// Reads whether this phone approves, the account's Macs and their unlock state, and gives the
    /// Notification Service Extension the Mac names.
    public func refresh() async {
        let approverKeys = self.approverKeys
        let keyring = self.keyring
        let (hasKeys, enrolled) = await Task.detached {
            ((try? approverKeys.load()) != nil, Set((try? keyring.macs()) ?? []))
        }.value
        guard let (approvers, me) = try? await vault.read({ core in (try core.approvers(), core.thisDeviceId()) })
        else { return }
        isEnabled = hasKeys && approvers.contains { $0.deviceId == me && $0.role == .phone }
        let now = Date()
        windows = windows.filter { $0.value > now }
        macs = approvers.filter { $0.role == .mac }.map {
            Mac(id: $0.deviceId, name: $0.deviceName, unlockEnrolled: enrolled.contains($0.deviceId),
                windowEndsAt: windows[$0.deviceId])
        }
        sharedDefaults?.set(macs.map(\.name), forKey: Self.macNamesKey)
    }

    private func dropRevokedAndRefresh() async {
        await responder?.dropRevokedMacs()
        await refresh()
    }

    /// Makes this iPhone an approver (spec 4): its approval keys (this device only) join the signed
    /// list, the Face ID item every answer reads is written, and the CloudKit push is subscribed.
    public func enable() async throws {
        let approverKeys = self.approverKeys
        let keyring = self.keyring
        let keys = try await Task.detached { () throws -> FfiApproverKeys in
            try keyring.armPresence()
            return try approverKeys.loadOrCreate()
        }.value
        try await vault.write { core in
            guard let me = core.thisDeviceId() else { throw VaultError.integrity(kind: "unregistered") }
            let listed = try core.approvers().contains { $0.deviceId == me && $0.role == .phone }
            if !listed { try core.registerApprover(keys: keys, role: .phone) }
        }
        #if canImport(CloudKit)
        if let cloud = channel as? CloudKitRemoteChannel, let me = vault.coreSession?.thisDeviceId() {
            try? await cloud.subscribe(device: me)
        }
        #endif
        await sessionChanged()
        await refresh()
    }

    // MARK: - Answers

    public func answer(_ request: OpenedRequest, decision: FfiRemoteDecision) async throws {
        guard let responder else { throw RemoteResponderError.unknownRequest }
        try await responder.answer(request.id, decision: decision)
        if request.isUnlock, decision != .denied {
            // Requested, not confirmed: the Mac sends nothing back when the window opens.
            let minutes = Double(request.body.windowMinutes ?? 60)
            windows[request.mac] = Date().addingTimeInterval(minutes * 60)
        }
        record(request, decision: Self.decisionLabel(decision))
        await pull()
        await refresh()
    }

    public func acceptEnrollment(_ request: OpenedRequest) async throws {
        guard let responder else { throw RemoteResponderError.unknownRequest }
        try await responder.acceptEnrollment(request.id)
        record(request, decision: String(localized: "Déverrouillage à distance activé", bundle: VaultKitStrings.bundle))
        await pull()
        await refresh()
    }

    /// "Réactiver Face ID": the gate written again for the current biometric set, after a Face ID
    /// of that set, with the vault open.
    public func reArmFaceID() async throws {
        guard vault.state == .unlocked, let responder else { throw RemoteResponderError.unavailable }
        try await responder.reArmFaceID()
        await pull()
    }

    /// A pairing refused: nothing is sent.
    public func dismiss(_ request: OpenedRequest) async {
        await responder?.dismiss(request.id)
        await pull()
    }

    public func forget(mac: String) async throws {
        guard let responder else { throw RemoteResponderError.unavailable }
        defer { Task { await self.refresh() } }
        try await responder.forget(mac: mac)
    }

    public func lockNow(mac: String) async throws {
        guard let responder else { throw RemoteResponderError.unavailable }
        try await responder.lockNow(mac: mac)
        windows.removeValue(forKey: mac)
        await refresh()
    }

    // MARK: - Journal

    private func record(_ request: OpenedRequest, decision: String) {
        let line = LogLine(
            id: UUID(), date: Date(), mac: request.macName, client: request.body.client,
            action: request.body.action, decision: decision)
        log = Array(([line] + log).prefix(Self.logLimit))
        if let data = try? JSONEncoder().encode(log) { defaults.set(data, forKey: Self.logKey) }
    }

    static func decisionLabel(_ decision: FfiRemoteDecision) -> String {
        switch decision {
        case .denied: String(localized: "Refusé", bundle: VaultKitStrings.bundle)
        case .once: String(localized: "Autorisé une fois", bundle: VaultKitStrings.bundle)
        case .grant5m: String(localized: "Autorisé 5 min", bundle: VaultKitStrings.bundle)
        }
    }
}
