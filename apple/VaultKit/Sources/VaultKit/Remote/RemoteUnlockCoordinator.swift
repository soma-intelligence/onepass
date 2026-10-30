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
/// Flow (spec 6.2, two steps): an agent connects to the locked Mac, the gate answers its handshake
/// itself and, on its first tool call (a paired client only), calls `handleLockedRequest`; the
/// enrolled iPhone is asked to unlock (the agent's identity and the window only); its approval opens
/// an agents-only session (`RemoteUnlocker.finish`) that the MCP and SSH servers serve while the app
/// stays locked. That tool request then goes through the usual approval race (panel and iPhone)
/// with its code. A full unlock of the Mac while the phone is asked ends the wait: the agent goes
/// to the full session.
///
/// The window ends at its deadline (a timer: the core keeps the keys until the next use after the
/// deadline), when the Mac goes to sleep or the user session goes inactive, on a `Lock` notice from
/// a phone, on a lock of the app, or when the owner unlocks for real. The screens going to sleep do
/// not end it (a panel answer needs Touch ID during a window). A relaunch starts locked (nothing is
/// persisted but `C`).
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
    /// The Mac's one reader of its remote messages (shared with the window's approver).
    @ObservationIgnored private var mailbox: RemoteMailbox?
    /// The notice consumer while a window is open.
    @ObservationIgnored private var noticeSubscription: (RemoteMailbox, UUID)?
    /// Bumped by `lockNow` and every end of a window: an answer that arrives after it never opens one.
    @ObservationIgnored private var generation = 0
    /// The approver the window's first tool request races with (tests read it).
    @ObservationIgnored private(set) var windowApprover: RemoteApprover?
    /// Tests: runs after the phone's approval, right before the window opens.
    @ObservationIgnored var beforeOpenWindow: ((Session) async -> Void)?
    /// Tests: runs once the servers started on the window, before the last check.
    @ObservationIgnored var whileServersStart: (() async -> Void)?
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
        vault.agentWindowEnded = { [weak self] in self?.windowClosed() }
        hosts.fullUnlockHandler = { [weak self] in self?.fullyUnlocked() }
        vault.passwordChangedHere = { [weak self] in self?.forgetAll() }
        vault.devicesRefreshed = { [weak self] in self?.devicesRefreshed($0) }
        for name in Self.endingNotifications {
            observers.append(notifications.addObserver(forName: name, object: nil, queue: nil) { [weak self] _ in
                Task { @MainActor in self?.lockNow() }
            })
        }
    }

    isolated deinit {
        for observer in observers { notifications.removeObserver(observer) }
        deadline?.cancel()
        pending?.cancel()
    }

    public static var defaultNotifications: NotificationCenter {
        #if os(macOS)
        NSWorkspace.shared.notificationCenter
        #else
        NotificationCenter.default
        #endif
    }

    /// Mac asleep, user session switched out (spec 6.3). The screens going to sleep end nothing: the
    /// panel's answers need Touch ID while a window is open, so an unattended Mac approves nothing.
    static var endingNotifications: [Notification.Name] {
        #if os(macOS)
        [NSWorkspace.willSleepNotification, NSWorkspace.sessionDidResignActiveNotification]
        #else
        []
        #endif
    }

    static var enrollPrompt: String {
        String(localized: "Activer le déverrouillage depuis ton iPhone", bundle: VaultKitStrings.bundle)
    }

    // MARK: - Launch

    /// At launch: reads the enrollment (off the main actor), erases the expired records of a quit
    /// or a sleep (Review Focus 4), and a locked, enrolled Mac holds the MCP socket with the gate.
    public func start() async {
        let store = self.store
        let entry = await Self.offMain { try? store.load() }
        enrolledPhone = entry?.phone
        if entry != nil { installGateHandler() }
        await channel.purgeExpired(now: now())
        if enrolledPhone != nil, vault.state == .locked, vault.agentSession == nil { hosts.armGate() }
    }

    /// Keychain reads never run on the main actor.
    nonisolated private static func offMain<T: Sendable>(_ work: @escaping @Sendable () -> T) async -> T {
        await Task.detached(priority: .userInitiated) { work() }.value
    }

    /// The one reader of `device`'s messages (this Mac's id). Every `RemoteApprover` of this Mac
    /// must use it, the full-unlock one included, so one reader routes every message.
    public func mailbox(for device: String) -> RemoteMailbox {
        if let mailbox, mailbox.device == device { return mailbox }
        let box = RemoteMailbox(channel: channel, device: device, now: now)
        mailbox = box
        return box
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
        let keys = try await macApproverKeys(register: true)
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

    /// This Mac's approval keys (created when missing); `register`: they join the signed approver
    /// list when they are not in it yet, so a phone trusts this Mac's requests.
    private func macApproverKeys(register: Bool) async throws -> FfiApproverKeys {
        let approverKeys = self.approverKeys
        let (hadKeys, keys) = try await Task.detached { () throws -> (Bool, FfiApproverKeys) in
            let had = try approverKeys.load() != nil
            return (had, try approverKeys.loadOrCreate())
        }.value
        guard register else { return keys }
        try await vault.write { core in
            guard let me = core.thisDeviceId() else { throw VaultError.integrity(kind: "unregistered") }
            let listed = try core.approvers().contains { $0.deviceId == me && $0.role == .mac }
            if !hadKeys || !listed { try core.registerApprover(keys: keys, role: .mac) }
        }
        return keys
    }

    /// The approver the panel races after a full unlock (spec 5.3), on this coordinator's mailbox:
    /// one reader of this Mac's messages, shared with the remote unlock. `register`: this Mac's keys
    /// join the signed list first (a phone is listed to trust them).
    public func makeApprover(register: Bool) async throws -> RemoteApprover {
        guard vault.state == .unlocked, let core = vault.coreSession else { throw VaultError.passwordRequired }
        let keys = try await macApproverKeys(register: register)
        guard let me = try await CoreThread.run({ core.thisDeviceId() }) else {
            throw VaultError.integrity(kind: "unregistered")
        }
        let register: @Sendable () async -> Bool = { [weak self] in await self?.registerMacApprover() ?? false }
        return RemoteApprover(
            channel: channel, session: core, keys: keys, now: now, mailbox: mailbox(for: me), register: register)
    }

    /// A phone appeared after the approver was built: this Mac joins the signed list now.
    private func registerMacApprover() async -> Bool {
        guard vault.state == .unlocked else { return false }
        do {
            _ = try await macApproverKeys(register: true)
            return true
        } catch {
            Self.log.error("Mac approval keys not registered")
            return false
        }
    }

    /// Forgets the remote unlock with `phone` on this Mac: `C` is erased here and nothing is sent
    /// (the phone's `K_r` alone opens nothing).
    public func forget(phone: String) async {
        guard await currentPhone() == phone else { return }
        clearEnrollment()
    }

    /// The enrolled phone, read from the keychain (off the main actor) when `start()` has not yet.
    private func currentPhone() async -> String? {
        if let enrolledPhone { return enrolledPhone }
        let store = self.store
        return await Self.offMain { try? store.load() }?.phone
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

    /// A device list read while unlocked (the verified list): an enrolled phone now revoked, or
    /// without an active approver entry (keys retired), loses its pairing (spec 6.4), reported like
    /// a stale enrollment (enroll again).
    private func devicesRefreshed(_ devices: [FfiDevice]) {
        Task { await checkPairing(devices) }
    }

    private func checkPairing(_ devices: [FfiDevice]) async {
        guard let phone = await currentPhone() else { return }
        let revoked = devices.contains { $0.id == phone && $0.revokedAt != nil }
        var approver = true
        if !revoked, let list = try? await vault.read({ try $0.approvers() }) {
            approver = list.contains { $0.deviceId == phone && $0.role == .phone }
        }
        guard revoked || !approver else { return }
        clearEnrollment()
        lastFailure = .staleEnrollment
    }

    // MARK: - Locked request

    /// An agent connected while the app is locked (the gate asks, spec 6.2): asks the enrolled phone
    /// to unlock for the agents, and opens the agents-only window on its approval. True when a
    /// session now serves the agents. The whole of it (request, wait, hand-over) is bounded by
    /// `timeout` (60 s): false at the latest then, and an approval after that opens nothing.
    /// Concurrent agents share one request.
    public func handleLockedRequest(client: FfiMcpClient) async -> Bool {
        if vault.state == .unlocked || vault.agentSession != nil { return true }
        let task: Task<Bool, Never>
        if let pending {
            task = pending
        } else {
            let deadline = ContinuousClock.now + timeout
            task = Task { await self.unlock(for: client, deadline: deadline) }
            pending = task
        }
        let limit = timeout
        let gen = generation
        let ok = await withTaskGroup(of: Bool?.self) { group in
            group.addTask { await task.value }
            group.addTask {
                try? await Task.sleep(for: limit)
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
        if pending == task { pending = nil }
        // The owner unlocked the Mac meanwhile: the full session serves the agent.
        if vault.state == .unlocked { return true }
        guard let ok else {
            // Out of time: the request still running must not open a window any more.
            if generation == gen { abandon(task) }
            return refuse(.timedOut)
        }
        return ok
    }

    /// The owner unlocked the Mac for real (`DeveloperHosts.sessionUnlocked`): a request waiting on
    /// the phone ends at once, opens no window, and its agent goes to the full session (the gate
    /// hands over to the server started on it).
    private func fullyUnlocked() {
        guard let pending else { return }
        abandon(pending)
    }

    /// A request ran out of time: whatever it still does opens no window (and closes one it is
    /// opening).
    private func abandon(_ task: Task<Bool, Never>?) {
        generation &+= 1
        task?.cancel()
    }

    /// Tests: what the 60 s limit does to the request in flight.
    func abandonPendingRequestForTesting() {
        abandon(pending)
    }

    private enum Outcome: Sendable {
        case opened(Session)
        case stale, denied, expired, forgotten, timedOut
    }

    private func unlock(for client: FfiMcpClient, deadline: ContinuousClock.Instant) async -> Bool {
        let gen = generation
        guard vault.state == .locked else { return false }
        let store = self.store
        let approverKeys = self.approverKeys
        let (entry, keys) = await Self.offMain { (try? store.load(), try? approverKeys.load()) }
        guard let entry else { return false }
        guard let keys else { return refuse(.unavailable) }
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
        } catch {
            // `C` is erased only from the verified device list (`devicesRefreshed`), never on a
            // refusal here.
            Self.log.error("remote unlock request not sealed")
            return refuse(.unavailable)
        }
        let record = "unlock-" + RemoteApprover.hex(sealed.requestId)
        let channel = self.channel
        let message = RemoteMessage(
            id: record, to: sealed.to, blob: sealed.blob,
            expiresAt: Date(timeIntervalSince1970: TimeInterval(sealed.expiresAt)))
        let posted = await Self.within(deadline) { () -> Bool in
            do {
                try await channel.post(message)
                return true
            } catch {
                return false
            }
        }
        guard posted == true else {
            Task { await channel.delete(record) }
            return refuse(posted == nil ? .timedOut : .unavailable)
        }
        let outcome = await waitForAnswer(unlocker: unlocker, entry: entry, deadline: deadline)
        // Withdrawn off the critical path.
        Task { await channel.delete(record) }
        if vault.state == .unlocked {
            // A full unlock ended the wait: nothing failed, and a session the phone opened anyway
            // is not used.
            if case .opened(let session) = outcome { Self.lockOffMain(session) }
            return true
        }

        switch outcome {
        case .opened(let session):
            if let beforeOpenWindow { await beforeOpenWindow(session) }
            // A lock, a sleep or the deadline came in meanwhile: nothing opens.
            guard gen == generation, !Task.isCancelled, ContinuousClock.now < deadline, vault.state == .locked else {
                Self.lockOffMain(session)
                return vault.state == .unlocked ? true : refuse(.timedOut)
            }
            let endsAt = session.agentWindowEndsAt().map { Date(timeIntervalSince1970: TimeInterval($0)) }
                ?? now().addingTimeInterval(TimeInterval(window) * 60)
            guard endsAt > now() else {
                // The window is already over: closed at once.
                Self.lockOffMain(session)
                return refuse(.timedOut)
            }
            guard await openWindow(session, endsAt: endsAt, entry: entry, keys: keys, unlocker: unlocker) else {
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

    nonisolated private static func lockOffMain(_ session: Session) {
        Task { _ = try? await CoreThread.run { session.lock() } }
    }

    /// `work`'s result, or nil once `deadline` passed.
    nonisolated private static func within<T: Sendable>(
        _ deadline: ContinuousClock.Instant, _ work: @escaping @Sendable () async -> T
    ) async -> T? {
        await withTaskGroup(of: T?.self) { group in
            group.addTask { await work() }
            group.addTask {
                try? await Task.sleep(until: deadline, clock: .continuous)
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
    }

    /// The first conclusive message for this request through the Mac's mailbox (notices first,
    /// then the answer), or `.timedOut` at `deadline`. A session opened after the deadline won is
    /// locked at once.
    private func waitForAnswer(
        unlocker: RemoteUnlocker, entry: RemoteUnlockKeyStore.Entry, deadline: ContinuousClock.Instant
    ) async -> Outcome {
        let box = mailbox(for: entry.mac)
        let (results, sink) = AsyncStream.makeStream(of: Outcome.self)
        let phone = entry.phone
        let c = entry.c
        let notices = await box.register(.notice) { message in
            let blob = message.blob
            guard let notice = try? await CoreThread.run({
                try unlocker.openRemoteNotice(blob: blob, enrolledPhone: phone)
            }) else { return false }
            if notice.kind == .forgetUnlock { sink.yield(.forgotten) }
            return true
        }
        let answers = await box.register(.unlock) { message in
            let blob = message.blob
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
                // Forged, misdirected, or not an unlock answer: left alone, the wait goes on.
                return false
            }
            // The wait already ended: a session nobody will use is locked at once.
            if case .terminated = sink.yield(outcome), case .opened(let session) = outcome {
                Self.lockOffMain(session)
            }
            return true
        }
        let timer = Task {
            try? await Task.sleep(until: deadline, clock: .continuous)
            sink.yield(.timedOut)
        }
        // A lock or sleep while waiting (the request task is cancelled) ends the wait too.
        let outcome = await withTaskCancellationHandler {
            var first: Outcome = .timedOut
            for await outcome in results {
                first = outcome
                break
            }
            return first
        } onCancel: {
            sink.yield(.timedOut)
        }
        timer.cancel()
        await box.unregister(notices)
        await box.unregister(answers)
        sink.finish()
        // An approval that came after the outcome was decided: its session is locked at once.
        for await late in results {
            if case .opened(let session) = late { Self.lockOffMain(session) }
        }
        if case .opened(let session) = outcome, ContinuousClock.now >= deadline {
            Self.lockOffMain(session)
            return .timedOut
        }
        return outcome
    }

    // MARK: - Agents-only window

    private func openWindow(
        _ session: Session, endsAt: Date, entry: RemoteUnlockKeyStore.Entry, keys: FfiApproverKeys,
        unlocker: RemoteUnlocker
    ) async -> Bool {
        guard vault.openAgentWindow(session, endsAt: endsAt) else { return false }
        let gen = generation
        startDeadline(endsAt)
        let box = mailbox(for: entry.mac)
        await startNotices(box: box, phone: entry.phone, unlocker: unlocker)
        // Ended while the notices started: nothing stays armed.
        guard gen == generation else {
            stopNotices()
            closeAbandoned(session)
            return false
        }
        let store = vault.environment.databaseURL.deletingLastPathComponent().path
        let approver = RemoteApprover(channel: channel, session: session, keys: keys, now: now, mailbox: box)
        windowApprover = approver
        await hosts.agentWindowOpened(session, store: store, approver: approver)
        if let whileServersStart { await whileServersStart() }
        // Ended while the servers started (lock, sleep, time out): everything stops again.
        if gen != generation || vault.agentSession !== session {
            closeAbandoned(session)
            return false
        }
        return true
    }

    /// A window given up while it opened: closed like any end (session locked, timer and
    /// consumers gone, servers stopped), or only the servers stopped if it already closed.
    private func closeAbandoned(_ session: Session) {
        retireWindowApprover()
        if vault.agentSession === session {
            vault.endAgentWindow()
        } else {
            hosts.agentWindowEnded(rearm: vault.state == .locked && enrolledPhone != nil)
        }
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
    /// enrolled phone erases `C`. Through the Mac's mailbox, ahead of the approval answers.
    private func startNotices(box: RemoteMailbox, phone: String, unlocker: RemoteUnlocker) async {
        stopNotices()
        let id = await box.register(.notice) { [weak self] message in
            let blob = message.blob
            guard let notice = try? await CoreThread.run({
                try unlocker.openRemoteNotice(blob: blob, enrolledPhone: phone)
            }) else { return false }
            await MainActor.run {
                switch notice.kind {
                case .lock: self?.lockNow()
                case .forgetUnlock: self?.clearEnrollment()
                }
            }
            return true
        }
        noticeSubscription = (box, id)
    }

    private func stopNotices() {
        guard let (box, id) = noticeSubscription else { return }
        noticeSubscription = nil
        Task { await box.unregister(id) }
    }

    /// "Verrouiller maintenant": ends the agents-only window, and any unlock request waiting (an
    /// approval that arrives after this opens nothing).
    public func lockNow() {
        generation &+= 1
        pending?.cancel()
        vault.endAgentWindow()
    }

    /// The vault ended the window (lock, deadline, notice, sleep, full unlock).
    private func windowClosed() {
        generation &+= 1
        deadline?.cancel()
        deadline = nil
        stopNotices()
        // The window's approver stops reading, even with a request still unexpired. Only its own
        // consumer leaves the shared mailbox: a full-unlock approver on it keeps its answers.
        retireWindowApprover()
        hosts.agentWindowEnded(rearm: vault.state == .locked && enrolledPhone != nil)
    }

    private func retireWindowApprover() {
        guard let approver = windowApprover else { return }
        windowApprover = nil
        Task { await approver.stop() }
    }
}
