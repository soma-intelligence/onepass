import Foundation
import OnePassCore
import Observation
import os

#if os(macOS)
import AppKit
#endif

/// Mac side of the remote unlock (agent-ready spec 6): enrollment (`C` in this Mac's keychain),
/// the locked request the MCP gate asks, the agents-only window it opens and everything that ends
/// it.
///
/// Flow (spec 6.2, two steps): an agent connects to the locked Mac, the gate calls
/// `handleLockedRequest`, the enrolled iPhone is asked to unlock (the agent's identity and the
/// window only); its approval opens an agents-only session (`RemoteUnlocker.finish`) that the MCP and
/// SSH servers serve while the app stays locked. The first tool request then goes through the usual
/// approval race (panel and iPhone) with its code.
///
/// The window ends at its deadline (a timer: the core keeps the keys until the next use after the
/// deadline), when the Mac goes to sleep, its screens sleep or the user session goes inactive, on a
/// `Lock` notice from a phone, on a lock of the app, or when the owner unlocks for real. A relaunch
/// starts locked (nothing is persisted but `C`).
@MainActor
@Observable
public final class RemoteUnlockCoordinator {
    /// Why the last remote unlock did not open (for the settings, Task 10).
    public enum Failure: Equatable, Sendable {
        /// The master password changed on another device: `C` was erased, enroll again.
        case staleEnrollment
        /// One request per 10 minutes, and 3 refusals block for an hour.
        case throttled
        /// The phone refused.
        case denied
        /// No answer in time.
        case timedOut
        /// CloudKit unreachable, approval keys missing, or the phone left the approver list.
        case unavailable

        public var message: String {
            switch self {
            case .staleEnrollment:
                String(localized: "Ton mot de passe maître a changé : réactive le déverrouillage depuis ton iPhone.", bundle: VaultKitStrings.bundle)
            case .throttled:
                String(localized: "Trop de demandes de déverrouillage : réessaie plus tard.", bundle: VaultKitStrings.bundle)
            case .denied:
                String(localized: "Déverrouillage refusé sur l'iPhone.", bundle: VaultKitStrings.bundle)
            case .timedOut:
                String(localized: "L'iPhone n'a pas répondu à temps.", bundle: VaultKitStrings.bundle)
            case .unavailable:
                String(localized: "iPhone injoignable : déverrouille l'app sur ce Mac.", bundle: VaultKitStrings.bundle)
            }
        }
    }

    /// A locked request is answered within this time (spec 6.2.4), false at the latest then.
    public static let requestTimeout: Duration = .seconds(60)

    /// The phone whose `K_r` pairs with this Mac's `C`, nil when not enrolled.
    public private(set) var enrolledPhone: String?
    public private(set) var lastFailure: Failure?

    @ObservationIgnored private let vault: VaultSession
    @ObservationIgnored private let hosts: DeveloperHosts
    @ObservationIgnored private let channel: any RemoteChannel
    @ObservationIgnored private let approverKeys: ApproverKeyStore
    @ObservationIgnored private let store: RemoteUnlockKeyStore
    @ObservationIgnored private let timeout: Duration
    @ObservationIgnored private let windowTimer: @Sendable (Duration) async throws -> Void
    @ObservationIgnored private let now: @Sendable () -> Date
    @ObservationIgnored private let notifications: NotificationCenter
    @ObservationIgnored private var observers: [any NSObjectProtocol] = []
    @ObservationIgnored private var pending: Task<Bool, Never>?
    @ObservationIgnored private var deadline: Task<Void, Never>?
    @ObservationIgnored private var noticeListener: Task<Void, Never>?
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "remote")

    /// `notifications`: where sleep and session changes are posted (the workspace center on the
    /// Mac). `timeout`: the answer wait (60 s). `windowTimer`: sleeps until the window's deadline
    /// (tests hold it). The keychain stores default to the system keychain of this Mac.
    public init(
        vault: VaultSession, hosts: DeveloperHosts, channel: any RemoteChannel,
        approverKeys: ApproverKeyStore = ApproverKeyStore(), store: RemoteUnlockKeyStore = RemoteUnlockKeyStore(),
        notifications: NotificationCenter = RemoteUnlockCoordinator.defaultNotifications,
        timeout: Duration = RemoteUnlockCoordinator.requestTimeout,
        windowTimer: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.vault = vault
        self.hosts = hosts
        self.channel = channel
        self.approverKeys = approverKeys
        self.store = store
        self.notifications = notifications
        self.timeout = timeout
        self.windowTimer = windowTimer
        self.now = now
        enrolledPhone = (try? store.load())?.phone
        vault.agentWindowEnded = { [weak self] in self?.windowClosed() }
        vault.passwordChangedHere = { [weak self] in self?.forgetAll() }
        vault.devicesRefreshed = { [weak self] in self?.devicesRefreshed($0) }
        if enrolledPhone != nil { installGateHandler() }
        for name in Self.endingNotifications {
            observers.append(notifications.addObserver(forName: name, object: nil, queue: nil) { [weak self] _ in
                Task { @MainActor in self?.lockNow() }
            })
        }
    }

    isolated deinit {
        for observer in observers { notifications.removeObserver(observer) }
        deadline?.cancel()
        noticeListener?.cancel()
        pending?.cancel()
    }

    public static var defaultNotifications: NotificationCenter {
        #if os(macOS)
        NSWorkspace.shared.notificationCenter
        #else
        NotificationCenter.default
        #endif
    }

    /// Mac asleep, screens asleep, user session switched out (spec 6.3).
    static var endingNotifications: [Notification.Name] {
        #if os(macOS)
        [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification,
         NSWorkspace.sessionDidResignActiveNotification]
        #else
        []
        #endif
    }

    static var enrollPrompt: String {
        String(localized: "Activer le déverrouillage depuis ton iPhone", bundle: VaultKitStrings.bundle)
    }

    // MARK: - Launch

    /// At launch: the expired records of a quit or a sleep are erased (Review Focus 4), and a
    /// locked, enrolled Mac holds the MCP socket with the gate.
    public func start() async {
        await channel.purgeExpired(now: now())
        if enrolledPhone != nil, vault.state == .locked, vault.agentSession == nil { hosts.armGate() }
    }

    // MARK: - Enrollment

    /// Enrolls `phone` (spec 6.1): Touch ID first (it releases the AUK), then the core seals the AUK
    /// under a fresh `K_r` and the `Pair` request carrying `K_r` goes to the phone; `C` stays in
    /// this Mac's keychain. Replaces an earlier enrollment. Unlocked vault with Touch ID unlock on.
    /// Returns the two letters the phone shows too.
    @discardableResult
    public func enroll(phone: String) async throws -> String {
        guard vault.state == .unlocked, vault.coreSession != nil else { throw VaultError.passwordRequired }
        let auk = try await vault.accountKeyWithTouchID(prompt: Self.enrollPrompt)
        defer { auk.wipe() }
        let hadKeys = try approverKeys.load() != nil
        let keys = try approverKeys.loadOrCreate()
        // This Mac's approval keys must be in the signed list for the phone to trust its requests.
        try await vault.write { core in
            guard let me = core.thisDeviceId() else { throw VaultError.integrity(kind: "unregistered") }
            let listed = try core.approvers().contains { $0.deviceId == me && $0.role == .mac }
            if !hadKeys || !listed { try core.registerApprover(keys: keys, role: .mac) }
        }
        guard let core = vault.coreSession else { throw VaultError.passwordRequired }
        let (enrollment, mac) = try await CoreThread.run { () -> (FfiEnrollment, String) in
            guard let me = core.thisDeviceId() else { throw VaultError.integrity(kind: "unregistered") }
            let enrollment = try auk.withData { try core.remoteUnlockEnroll(keys: keys, phone: phone, auk: $0) }
            return (enrollment, me)
        }
        let request = enrollment.transferRequest
        do {
            try await channel.post(RemoteMessage(
                id: "pair-" + RemoteApprover.hex(request.requestId), to: request.to, blob: request.blob,
                expiresAt: Date(timeIntervalSince1970: TimeInterval(request.expiresAt))))
        } catch {
            throw VaultError.other(Failure.unavailable.message)
        }
        try store.save(RemoteUnlockKeyStore.Entry(mac: mac, phone: phone, c: enrollment.c))
        enrolledPhone = phone
        lastFailure = nil
        installGateHandler()
        return enrollment.confirmCode
    }

    /// Forgets the remote unlock with `phone` on this Mac: `C` is erased here and nothing is sent
    /// (the phone's `K_r` alone opens nothing).
    public func forget(phone: String) async {
        guard enrolledPhone == phone || (try? store.load())?.phone == phone else { return }
        clearEnrollment()
    }

    /// Erases every `C` of this Mac (master password changed here, spec 6.1).
    public func forgetAll() {
        clearEnrollment()
    }

    private func clearEnrollment() {
        do {
            try store.delete()
        } catch {
            Self.log.error("remote unlock envelope not erased")
        }
        enrolledPhone = nil
        hosts.setLockedRequestHandler(nil)
    }

    private func installGateHandler() {
        hosts.setLockedRequestHandler { [weak self] client in
            await self?.handleLockedRequest(client: client) ?? false
        }
    }

    /// A device list read while unlocked: an enrolled phone now revoked loses its pairing (spec 6.4).
    private func devicesRefreshed(_ devices: [FfiDevice]) {
        guard let phone = enrolledPhone,
            devices.contains(where: { $0.id == phone && $0.revokedAt != nil })
        else { return }
        clearEnrollment()
    }

    // MARK: - Locked request

    /// An agent connected while the app is locked (the gate asks, spec 6.2): asks the enrolled phone
    /// to unlock for the agents, and opens the agents-only window on its approval. True when a
    /// session now serves the agents. Answers within `timeout` (60 s), false at the latest then.
    /// Concurrent agents share one request.
    public func handleLockedRequest(client: FfiMcpClient) async -> Bool {
        if vault.state == .unlocked || vault.agentSession != nil { return true }
        if let pending { return await pending.value }
        let task = Task { await self.unlock(for: client) }
        pending = task
        let ok = await task.value
        if pending == task { pending = nil }
        return ok
    }

    private enum Outcome: Sendable {
        case opened(Session)
        case stale, denied, expired, forgotten, timedOut
    }

    private func unlock(for client: FfiMcpClient) async -> Bool {
        let started = ContinuousClock.now
        guard vault.state == .locked, let entry = try? store.load() else { return false }
        guard let keys = try? approverKeys.load() else { return refuse(.unavailable) }
        let path = vault.dbPath
        let window = UInt32(hosts.settings.agentWindowMinutes)
        // The agent's identity and the window only (the tool request comes after, with its code).
        let body = FfiRequestBody(
            client: client.label, clientVerified: client.signed, action: "remote_unlock",
            details: [FfiDetail(label: String(localized: "Identifiant", bundle: VaultKitStrings.bundle), value: client.id)],
            targets: [], rememberAllowed: false, strongRequired: true, confirmCode: "", windowMinutes: nil)
        let unlocker: RemoteUnlocker
        let sealed: FfiSealedRequest
        do {
            (unlocker, sealed) = try await CoreThread.run {
                let unlocker = try RemoteUnlocker(dbPath: path, macKeys: keys)
                return (unlocker, try unlocker.begin(phoneId: entry.phone, body: body, windowMinutes: window))
            }
        } catch OnePassError.Validation(let field, let reason) where field == "remote_unlock" && reason == "throttled" {
            return refuse(.throttled)
        } catch OnePassError.NotFound {
            // The phone left the approver list (revoked, or its keys retired): its half is useless.
            clearEnrollment()
            return refuse(.unavailable)
        } catch {
            Self.log.error("remote unlock request not sealed")
            return refuse(.unavailable)
        }
        let record = "unlock-" + RemoteApprover.hex(sealed.requestId)
        do {
            try await channel.post(RemoteMessage(
                id: record, to: sealed.to, blob: sealed.blob,
                expiresAt: Date(timeIntervalSince1970: TimeInterval(sealed.expiresAt))))
        } catch {
            return refuse(.unavailable)
        }
        let left = timeout - (ContinuousClock.now - started)
        let outcome = await Self.waitForAnswer(
            channel: channel, unlocker: unlocker, entry: entry, within: max(left, .zero))
        await channel.delete(record)

        switch outcome {
        case .opened(let session):
            let endsAt = session.agentWindowEndsAt().map { Date(timeIntervalSince1970: TimeInterval($0)) }
                ?? now().addingTimeInterval(TimeInterval(window) * 60)
            guard await openWindow(session, endsAt: endsAt, entry: entry, keys: keys, unlocker: unlocker) else {
                // Unlocked meanwhile: the full session serves.
                return vault.state == .unlocked
            }
            lastFailure = nil
            return true
        case .stale:
            // Password changed elsewhere: erased, reported, no new request until enrolled again.
            clearEnrollment()
            return refuse(.staleEnrollment)
        case .denied:
            return refuse(.denied)
        case .expired, .timedOut:
            return refuse(.timedOut)
        case .forgotten:
            clearEnrollment()
            return refuse(.unavailable)
        }
    }

    private func refuse(_ failure: Failure) -> Bool {
        lastFailure = failure
        return false
    }

    /// The first conclusive message for this Mac, or `.timedOut` after `within`.
    nonisolated private static func waitForAnswer(
        channel: any RemoteChannel, unlocker: RemoteUnlocker, entry: RemoteUnlockKeyStore.Entry, within: Duration
    ) async -> Outcome {
        let stream = channel.messages(for: entry.mac)
        return await withTaskGroup(of: Outcome?.self) { group in
            group.addTask {
                for await message in stream {
                    if let outcome = await consider(message, channel: channel, unlocker: unlocker, entry: entry) {
                        return outcome
                    }
                }
                return nil
            }
            group.addTask {
                try? await Task.sleep(for: within)
                return .timedOut
            }
            var result = Outcome.timedOut
            while let next = await group.next() {
                if let next {
                    result = next
                    break
                }
            }
            group.cancelAll()
            return result
        }
    }

    /// A notice (`ForgetUnlock` ends the wait, `Lock` has nothing to end), then an answer to the
    /// request. Anything else (forged, misdirected, another request's answer) is left alone.
    nonisolated private static func consider(
        _ message: RemoteMessage, channel: any RemoteChannel, unlocker: RemoteUnlocker,
        entry: RemoteUnlockKeyStore.Entry
    ) async -> Outcome? {
        let blob = message.blob
        let phone = entry.phone
        if let notice = try? await CoreThread.run({ try unlocker.openRemoteNotice(blob: blob, enrolledPhone: phone) }) {
            await channel.delete(message.id)
            return notice.kind == .forgetUnlock ? .forgotten : nil
        }
        let c = entry.c
        let outcome: Outcome
        do {
            outcome = .opened(try await CoreThread.run { try unlocker.finish(responseBlob: blob, c: c) })
        } catch OnePassError.RemoteUnlockStale {
            outcome = .stale
        } catch OnePassError.Validation(let field, let reason) where field == "remote_unlock" && reason == "denied" {
            outcome = .denied
        } catch OnePassError.Integrity(let kind) where kind == "remote_expired" {
            outcome = .expired
        } catch {
            return nil
        }
        await channel.delete(message.id)
        return outcome
    }

    // MARK: - Agents-only window

    private func openWindow(
        _ session: Session, endsAt: Date, entry: RemoteUnlockKeyStore.Entry, keys: FfiApproverKeys,
        unlocker: RemoteUnlocker
    ) async -> Bool {
        guard vault.openAgentWindow(session, endsAt: endsAt) else { return false }
        startDeadline(endsAt)
        startNoticeListener(entry: entry, unlocker: unlocker)
        let store = vault.environment.databaseURL.deletingLastPathComponent().path
        let approver = RemoteApprover(channel: channel, session: session, keys: keys)
        await hosts.agentWindowOpened(session, store: store, approver: approver)
        // Ended while the servers started: they stop again.
        if vault.agentSession !== session {
            hosts.agentWindowEnded(rearm: vault.state == .locked && enrolledPhone != nil)
            return false
        }
        return true
    }

    private func startDeadline(_ endsAt: Date) {
        deadline?.cancel()
        let timer = windowTimer
        let wait = max(0, endsAt.timeIntervalSince(now()))
        deadline = Task { [weak self] in
            do {
                try await timer(.milliseconds(Int64(wait * 1000)))
            } catch {
                return
            }
            guard !Task.isCancelled else { return }
            self?.lockNow()
        }
    }

    /// While the window is open: `Lock` from any active phone ends it, `ForgetUnlock` from the
    /// enrolled phone erases `C`.
    private func startNoticeListener(entry: RemoteUnlockKeyStore.Entry, unlocker: RemoteUnlocker) {
        noticeListener?.cancel()
        let stream = channel.messages(for: entry.mac)
        let channel = self.channel
        let phone = entry.phone
        noticeListener = Task { [weak self] in
            for await message in stream {
                let blob = message.blob
                guard let notice = try? await CoreThread.run({
                    try unlocker.openRemoteNotice(blob: blob, enrolledPhone: phone)
                }) else { continue }
                await channel.delete(message.id)
                guard let self else { return }
                switch notice.kind {
                case .lock: self.lockNow()
                case .forgetUnlock: self.clearEnrollment()
                }
            }
        }
    }

    /// "Verrouiller maintenant": ends the agents-only window (and any unlock request waiting).
    public func lockNow() {
        pending?.cancel()
        vault.endAgentWindow()
    }

    /// The vault ended the window (lock, deadline, notice, sleep, full unlock).
    private func windowClosed() {
        deadline?.cancel()
        deadline = nil
        noticeListener?.cancel()
        noticeListener = nil
        hosts.agentWindowEnded(rearm: vault.state == .locked && enrolledPhone != nil)
    }
}
