import AppKit
import Foundation
import Synchronization
import Testing

@testable import VaultKit

// MARK: - Fixture

/// The server accepts every pending row of `path`; returns them.
private func push(_ path: String) throws -> [FfiRecordChange] {
    let h = try openSyncStore(dbPath: path)
    let changes = try h.pendingChanges()
    for c in changes {
        try h.markPushed(kind: c.kind, id: c.id, version: c.version, serverMeta: Data("tag".utf8))
    }
    return changes
}

/// Push `from`, then fetch those rows into `to`.
private func sync(_ from: String, _ to: String) throws {
    let changes = try push(from)
    let h = try openSyncStore(dbPath: to)
    for c in changes {
        try h.stageRemote(record: FfiRemoteRecord(
            kind: c.kind, id: c.id, version: c.version, data: c.data, serverMeta: Data("tag".utf8)))
    }
    _ = try h.commitRemote()
}

/// A channel whose stored records the tests can list.
protocol ListableRemoteChannel: RemoteChannel {
    func stored() -> [RemoteMessage]
}

extension InMemoryRemoteChannel: ListableRemoteChannel {}

/// A fake CloudKit where each message reaches one reader only (the latest subscribed): two readers of
/// one device lose each other's messages, as two pollers racing to delete do over real CloudKit.
final class SingleDeliveryRemoteChannel: ListableRemoteChannel {
    private struct State {
        var records: [RemoteMessage] = []
        var delivered: Set<String> = []
        var subscribers: [(id: UUID, device: String, continuation: AsyncStream<RemoteMessage>.Continuation)] = []
    }
    private let state = Mutex(State())

    func stored() -> [RemoteMessage] { state.withLock { $0.records } }

    func post(_ m: RemoteMessage) async throws {
        let target = state.withLock { s -> AsyncStream<RemoteMessage>.Continuation? in
            s.records.removeAll { $0.id == m.id }
            s.records.append(m)
            guard let first = s.subscribers.last(where: { $0.device == m.to }) else { return nil }
            s.delivered.insert(m.id)
            return first.continuation
        }
        target?.yield(m)
    }

    func messages(for device: String) -> AsyncStream<RemoteMessage> {
        let (stream, continuation) = AsyncStream.makeStream(of: RemoteMessage.self)
        let id = UUID()
        state.withLock { s in
            for m in s.records where m.to == device && !s.delivered.contains(m.id) {
                s.delivered.insert(m.id)
                continuation.yield(m)
            }
            s.subscribers.append((id, device, continuation))
        }
        continuation.onTermination = { [weak self] _ in
            self?.state.withLock { $0.subscribers.removeAll { $0.id == id } }
        }
        return stream
    }

    func delete(_ id: String) async {
        state.withLock { $0.records.removeAll { $0.id == id } }
    }

    func purgeExpired(now: Date) async {
        state.withLock { $0.records.removeAll { $0.expiresAt < now } }
    }
}

/// The window timer of the coordinator, held by the test: `fire()` ends the wait.
final class ManualTimer: Sendable {
    private struct State {
        var waits: [(Duration, CheckedContinuation<Void, any Error>)] = []
        var requested: [Duration] = []
    }
    private let state = Mutex(State())

    var requested: [Duration] { state.withLock { $0.requested } }

    func sleep(_ d: Duration) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, any Error>) in
            state.withLock {
                $0.waits.append((d, c))
                $0.requested.append(d)
            }
        }
        try Task.checkCancellation()
    }

    func fire() {
        let waits = state.withLock { s in
            defer { s.waits = [] }
            return s.waits
        }
        for (_, c) in waits { c.resume() }
    }
}

/// A Mac (the `VaultSession` of the harness, account creator, Touch ID enrolled) and an iPhone paired
/// with a full grant, both registered as approvers, every list synced both ways; the coordinator of
/// the Mac on an in-memory channel, keychain, notification center and window timer.
@MainActor
final class RemoteUnlockFixture {
    struct Phone {
        let dir: URL
        let path: String
        let session: Session
        let secretKey: String
        let id: String
        let keys: FfiApproverKeys
    }

    let harness: SessionHarness
    let vault: VaultSession
    let hosts: DeveloperHosts
    let channel: any ListableRemoteChannel
    let now: @Sendable () -> Date
    let macKeychain: InMemoryKeychain
    let center = NotificationCenter()
    let timer = ManualTimer()
    let socketDir: URL
    let suite: String
    let macPath: String
    let macId: String
    let phone: Phone
    var coordinator: RemoteUnlockCoordinator!

    private init(
        harness: SessionHarness, vault: VaultSession, hosts: DeveloperHosts, macKeychain: InMemoryKeychain,
        socketDir: URL, suite: String, macId: String, phone: Phone, channel: any ListableRemoteChannel,
        now: @escaping @Sendable () -> Date
    ) {
        self.channel = channel
        self.now = now
        self.harness = harness
        self.macKeychain = macKeychain
        self.vault = vault
        self.hosts = hosts
        self.socketDir = socketDir
        self.suite = suite
        self.macPath = harness.environment.databaseURL.path
        self.macId = macId
        self.phone = phone
    }

    static func make(
        timeout: Duration = .seconds(600), channel: any ListableRemoteChannel = InMemoryRemoteChannel(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) async throws -> RemoteUnlockFixture {
        let harness = try SessionHarness()
        let vault = harness.makeSession()
        let secretKey = try await vault.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await vault.enrollBiometrics(password: testPassword)
        let macCore = try #require(vault.coreSession)
        let macPath = harness.environment.databaseURL.path
        let macId = try #require(macCore.thisDeviceId())
        let macKeychain = InMemoryKeychain()
        let macKeys = try ApproverKeyStore(keychain: macKeychain).loadOrCreate()

        let phoneDir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-phone-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: phoneDir, withIntermediateDirectories: true)
        let phonePath = phoneDir.appendingPathComponent("vault.sqlite").path
        let phone = try await CoreThread.run { () -> Phone in
            _ = try push(macPath)
            let now = Int64(Date().timeIntervalSince1970)
            let n = try PairingNewcomer(name: "iPhone de Camille", kind: .phone, mode: .personal, now: now)
            let a = try PairingApprover.begin(qrText: n.qrText(), hello: n.hello(), now: now)
            _ = try n.onKeyExchange(bytes: a.keyExchange(), now: now)
            _ = try a.onFrame(frame: try n.confirm())
            let frame = try a.sealFullGrant(session: macCore, secretKey: secretKey, mode: .personal, includePending: false)
            _ = try n.open(frame: frame)
            let unlocked = try n.importSnapshot(dbPath: phonePath, password: testPassword)
            let phoneSecret = n.takeSecretKey() ?? ""
            try sync(macPath, phonePath)
            try macCore.registerApprover(keys: macKeys, role: .mac)
            try sync(macPath, phonePath)
            let phoneKeys = try generateApproverKeys()
            try unlocked.session.registerApprover(keys: phoneKeys, role: .phone)
            try sync(phonePath, macPath)
            return Phone(
                dir: phoneDir, path: phonePath, session: unlocked.session, secretKey: phoneSecret,
                id: n.deviceId(), keys: phoneKeys)
        }

        let socketDir = URL(fileURLWithPath: "/tmp/op-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: socketDir, withIntermediateDirectories: true)
        let suite = "onepass.tests.remote.\(UUID().uuidString)"
        // A real signed program stands for the relay: the gate and the server check its identity.
        let hosts = DeveloperHosts(
            paths: DeveloperPaths(dataDirectory: socketDir, relay: URL(fileURLWithPath: "/usr/bin/true")),
            defaults: UserDefaults(suiteName: suite)!, presence: harness.presence)
        let fixture = RemoteUnlockFixture(
            harness: harness, vault: vault, hosts: hosts, macKeychain: macKeychain, socketDir: socketDir, suite: suite, macId: macId,
            phone: phone, channel: channel, now: now)
        fixture.coordinator = fixture.makeCoordinator(vault: vault, timeout: timeout)
        return fixture
    }

    func makeCoordinator(vault: VaultSession, timeout: Duration = .seconds(600)) -> RemoteUnlockCoordinator {
        let timer = self.timer
        return RemoteUnlockCoordinator(
            vault: vault, hosts: hosts, channel: channel,
            approverKeys: ApproverKeyStore(keychain: macKeychain),
            store: RemoteUnlockKeyStore(keychain: macKeychain),
            notifications: center, timeout: timeout,
            windowTimer: { try await timer.sleep($0) }, now: now)
    }

    var store: RemoteUnlockKeyStore { RemoteUnlockKeyStore(keychain: macKeychain) }

    /// Enrolls the phone from the Mac (Touch ID is the fake keyring), then the phone takes `K_r`.
    @discardableResult
    func enroll() async throws -> Data {
        try await coordinator.enroll(phone: phone.id)
        let request = try #require(channel.stored().first { $0.to == phone.id })
        let phone = self.phone
        let kr = try await CoreThread.run { () -> Data in
            _ = try phone.session.openRemoteRequest(keys: phone.keys, blob: request.blob)
            return try phone.session.acceptEnrollment(keys: phone.keys, requestBlob: request.blob)
        }
        await channel.delete(request.id)
        return kr
    }

    /// The phone answers the unlock request waiting for it.
    func phoneAnswersUnlock(kr: Data?, decision: FfiRemoteDecision) async throws {
        let channel = self.channel
        let phoneID = phone.id
        try await waitUntil { channel.stored().contains { $0.to == phoneID } }
        let request = try #require(channel.stored().first { $0.to == phone.id })
        let phone = self.phone
        let response = try await CoreThread.run { () -> Data in
            let opened = try phone.session.openRemoteRequest(keys: phone.keys, blob: request.blob)
            #expect(opened.kind == .approveAndUnlock)
            return try phone.session.sealRemoteResponse(
                keys: phone.keys, requestBlob: request.blob, decision: decision,
                unlockKey: decision == .denied ? nil : kr)
        }
        try await channel.post(RemoteMessage(
            id: "response-\(UUID().uuidString)", to: macId, blob: response, expiresAt: Date().addingTimeInterval(60)))
    }

    /// The phone sends a signed notice to the Mac.
    func phoneSends(_ kind: FfiNoticeKind) async throws {
        let phone = self.phone
        let mac = macId
        let sealed = try await CoreThread.run {
            try phone.session.sealRemoteNotice(keys: phone.keys, mac: mac, kind: kind)
        }
        try await channel.post(RemoteMessage(
            id: "notice-\(UUID().uuidString)", to: sealed.to, blob: sealed.blob,
            expiresAt: Date(timeIntervalSince1970: TimeInterval(sealed.expiresAt))))
    }

    /// Locks the Mac UI, like the app does.
    func lockMac() async {
        vault.lock()
        hosts.sessionLocked()
        await hosts.settle()
    }

    /// Enrolled, locked, then opened from the phone: an agents-only window.
    func openWindow() async throws {
        let kr = try await enroll()
        await lockMac()
        async let ok = coordinator.handleLockedRequest(client: client)
        try await phoneAnswersUnlock(kr: kr, decision: .once)
        #expect(await ok)
        #expect(vault.agentWindowEndsAt != nil)
    }

    let client = FfiMcpClient(id: "team:ABCDE12345:com.example.agent", label: "Agent Exemple", signed: true, chain: [])

    func cleanUp() {
        vault.lock()
        hosts.sessionLocked()
        phone.session.lock()
        harness.cleanUp()
        UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite)
        try? FileManager.default.removeItem(at: phone.dir)
        try? FileManager.default.removeItem(at: socketDir)
    }
}

// MARK: - Tests

/// Remote unlock on the Mac (agent-ready spec 6): the gate asks the coordinator, the phone opens an
/// agents-only window that serves the agents while the app stays locked.
@MainActor
@Suite("Remote unlock", .timeLimit(.minutes(5)))
struct RemoteUnlockTests {
    @Test func lockedRequestUnlocksAgentOnlyAndServes() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        await f.hosts.update({ $0.mcpEnabled = true }, session: f.vault)
        #expect(f.hosts.mcpRunning, "\(f.hosts.mcpError ?? "")")
        let kr = try await f.enroll()
        #expect(f.coordinator.enrolledPhone == f.phone.id)

        await f.lockMac()
        #expect(!f.hosts.mcpRunning)
        // Locked and enrolled: the gate holds the MCP socket.
        #expect(f.hosts.gateRunning)

        async let ok = f.coordinator.handleLockedRequest(client: f.client)
        try await f.phoneAnswersUnlock(kr: kr, decision: .once)
        #expect(await ok)

        // The MCP server runs on the agents-only session, handed over by the gate.
        #expect(f.hosts.mcpRunning)
        #expect(!f.hosts.gateRunning)
        let agent = try #require(f.vault.agentSession)
        #expect(agent.isAgentOnly())
        #expect(try await CoreThread.run { try agent.vaults() }.count == 1)
        #expect(f.vault.state == .locked)
        // The phone's records are gone.
        try await waitUntil { f.channel.stored().isEmpty }
        // The first tool request goes through the usual race, with the phone too.
        #expect(f.hosts.remoteApproverSet)
    }

    @Test func uiStaysLockedDuringAgentWindow() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let item = try await addItem(f.vault, title: "Jeton Atlas")
        var told: [Bool] = []
        f.vault.coreSessionChanged = { told.append($0 != nil) }
        try await f.openWindow()

        // Everything but the agents sees a locked vault.
        #expect(f.vault.state == .locked)
        #expect(f.vault.coreSession == nil)
        #expect(f.vault.summaries.isEmpty)
        #expect(f.vault.allVaults.isEmpty)
        #expect(!told.contains(true), "the browser bridge must never get the agents-only session")
        await #expect(throws: VaultError.passwordRequired) {
            _ = try await f.vault.loadItem(vaultID: item.vaultId, itemID: item.id)
        }
        await #expect(throws: VaultError.passwordRequired) {
            try await f.vault.changePassword(current: testPassword, new: "Autre cheval 43 !")
        }
        await #expect(throws: VaultError.self) {
            _ = try await f.vault.exportEncryptedBackup(
                password: SecretBytes(utf8: testPassword), passphrase: SecretBytes(utf8: "phrase longue 1234"))
        }
        #expect(try #require(f.vault.agentSession).isAgentOnly())

        // The owner unlocks for real: the window ends, the full session replaces it.
        try await f.vault.unlock(password: testPassword)
        #expect(f.vault.state == .unlocked)
        #expect(f.vault.agentWindowEndsAt == nil)
        #expect(f.vault.agentSession == nil)
    }

    @Test func windowEndsAtDeadline() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        try await f.openWindow()
        let agent = try #require(f.vault.agentSession)
        let ends = try #require(f.vault.agentWindowEndsAt)
        // The default window: one hour.
        #expect(abs(ends.timeIntervalSinceNow - 3600) < 120)
        try await waitUntil { !f.timer.requested.isEmpty }
        let wait = try #require(f.timer.requested.last)
        #expect(wait > .seconds(3480) && wait <= .seconds(3600))

        f.timer.fire()
        try await waitUntil { @MainActor in f.vault.agentWindowEndsAt == nil }
        #expect(f.vault.agentSession == nil)
        await f.hosts.settle()
        #expect(!f.hosts.mcpRunning)
        // The keys are gone, not just forgotten by Swift.
        try await waitUntil { (try? await CoreThread.run { try agent.vaults() }) == nil }
    }

    /// Mac asleep, screens asleep, or another user's session in front: the window ends.
    @Test(arguments: [
        NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification,
        NSWorkspace.sessionDidResignActiveNotification,
    ])
    func sleepEndsWindow(_ name: Notification.Name) async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        try await f.openWindow()
        let agent = try #require(f.vault.agentSession)
        f.center.post(name: name, object: nil)
        try await waitUntil { @MainActor in f.vault.agentWindowEndsAt == nil }
        #expect(f.vault.agentSession == nil)
        await f.hosts.settle()
        #expect(!f.hosts.mcpRunning)
        try await waitUntil { (try? await CoreThread.run { try agent.vaults() }) == nil }
    }

    @Test func lockMessageFromPhoneEndsWindow() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        try await f.openWindow()
        try await f.phoneSends(.lock)
        try await waitUntil { @MainActor in f.vault.agentWindowEndsAt == nil }
        #expect(f.vault.agentSession == nil)
        // A lock ends the window, the enrollment stays.
        #expect(f.coordinator.enrolledPhone == f.phone.id)
        try await waitUntil { f.channel.stored().isEmpty }
    }

    @Test func forgetNoticeFromPhoneClearsC() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        try await f.openWindow()
        try await f.phoneSends(.forgetUnlock)
        try await waitUntil { @MainActor in f.coordinator.enrolledPhone == nil }
        #expect(try f.store.load() == nil)
    }

    @Test func staleEnrollmentClearedAndReported() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let kr = try await f.enroll()
        await f.lockMac()
        // The master password changes on the phone; the Mac fetches it while locked.
        let phone = f.phone
        let macPath = f.macPath
        _ = try await CoreThread.run {
            _ = try phone.session.changePassword(current: testPassword, secretKey: phone.secretKey, new: "Nouveau cheval 77 !")
            try sync(phone.path, macPath)
        }

        async let ok = f.coordinator.handleLockedRequest(client: f.client)
        try await f.phoneAnswersUnlock(kr: kr, decision: .once)
        #expect(await ok == false)
        #expect(f.coordinator.lastFailure == .staleEnrollment)
        #expect(f.coordinator.enrolledPhone == nil)
        #expect(try f.store.load() == nil)
        #expect(f.vault.agentWindowEndsAt == nil)

        // No loop of requests: the next agent is refused at once, nothing goes to the phone.
        try await waitUntil { f.channel.stored().isEmpty }
        #expect(await f.coordinator.handleLockedRequest(client: f.client) == false)
        #expect(f.channel.stored().isEmpty)
        #expect(!f.hosts.gateRunning)
    }

    @Test func throttleRefusesSecondRequestWithinTenMinutes() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let kr = try await f.enroll()
        await f.lockMac()

        async let first = f.coordinator.handleLockedRequest(client: f.client)
        try await f.phoneAnswersUnlock(kr: kr, decision: .denied)
        #expect(await first == false)
        #expect(f.coordinator.lastFailure == .denied)
        try await waitUntil { f.channel.stored().isEmpty }

        #expect(await f.coordinator.handleLockedRequest(client: f.client) == false)
        #expect(f.coordinator.lastFailure == .throttled)
        #expect(f.channel.stored().isEmpty, "a throttled request never reaches the phone")
        // The enrollment stays.
        #expect(f.coordinator.enrolledPhone == f.phone.id)
    }

    @Test func noAnswerRefusesWithinTheTimeout() async throws {
        #expect(RemoteUnlockCoordinator.requestTimeout == .seconds(60))
        let f = try await RemoteUnlockFixture.make(timeout: .milliseconds(300))
        defer { f.cleanUp() }
        try await f.enroll()
        await f.lockMac()
        #expect(await f.coordinator.handleLockedRequest(client: f.client) == false)
        #expect(f.coordinator.lastFailure == .timedOut)
        // The request is withdrawn.
        try await waitUntil { f.channel.stored().isEmpty }
    }

    @Test func forgetDeletesCLocally() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        try await f.enroll()
        #expect(try f.store.load() != nil)
        #expect(f.channel.stored().isEmpty)

        await f.coordinator.forget(phone: f.phone.id)
        #expect(try f.store.load() == nil)
        #expect(f.coordinator.enrolledPhone == nil)
        // Only the phone tells the Mac: the Mac sends nothing.
        #expect(f.channel.stored().isEmpty)
    }

    @Test func appRelaunchStartsLocked() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        try await f.openWindow()
        // A record left by the quit, already expired.
        try await f.channel.post(RemoteMessage(
            id: "stale", to: f.phone.id, blob: Data([1]), expiresAt: Date().addingTimeInterval(-5)))

        // The process dies; a new one starts on the same store and keychain.
        let relaunched = f.harness.makeSession()
        let coordinator = f.makeCoordinator(vault: relaunched)
        await coordinator.start()
        #expect(relaunched.state == .locked)
        #expect(relaunched.agentWindowEndsAt == nil)
        #expect(relaunched.agentSession == nil)
        #expect(relaunched.coreSession == nil)
        // The enrollment survives, the expired records do not.
        #expect(coordinator.enrolledPhone == f.phone.id)
        #expect(!f.channel.stored().contains { $0.id == "stale" })
        relaunched.lock()
    }

    @Test func revokedPhoneClearsC() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        try await f.enroll()
        try await f.vault.revokeDevice(f.phone.id, password: testPassword)
        try await waitUntil { @MainActor in f.coordinator.enrolledPhone == nil }
        #expect(try f.store.load() == nil)
    }

    @Test func passwordChangeHereClearsAllC() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        try await f.enroll()
        try await f.vault.changePassword(current: testPassword, new: "Nouveau cheval 77 !")
        #expect(try f.store.load() == nil)
        #expect(f.coordinator.enrolledPhone == nil)
    }

    @Test func enrollmentNeedsTouchIDFirst() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        f.harness.keyring.failNextDecrypt(with: .cancelled)
        await #expect(throws: VaultError.self) { try await f.coordinator.enroll(phone: f.phone.id) }
        #expect(try f.store.load() == nil)
        #expect(f.channel.stored().isEmpty)
    }

    /// One reader routes the Mac's messages: with a channel that gives each message to one reader
    /// only, a phone's `Lock` sent while a tool approval waits on the phone still ends the window.
    @Test func lockFromPhoneWhileApprovalOutstandingEndsWindow() async throws {
        let f = try await RemoteUnlockFixture.make(channel: SingleDeliveryRemoteChannel())
        defer { f.cleanUp() }
        try await f.openWindow()
        let approver = try #require(f.coordinator.windowApprover)
        let phoneID = f.phone.id
        let asked = Task { await approver.ask(approvalRequest()) }
        try await waitUntil { f.channel.stored().contains { $0.to == phoneID } }

        try await f.phoneSends(.lock)
        try await waitUntil { @MainActor in f.vault.agentWindowEndsAt == nil }
        #expect(f.vault.agentSession == nil)
        asked.cancel()
        _ = await asked.value
    }

    /// A lock (or a sleep) between the phone's approval and the window: nothing opens, the session
    /// the phone opened is locked.
    @Test func lockNowBetweenAnswerAndWindowLeavesSessionLocked() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let kr = try await f.enroll()
        await f.lockMac()
        let opened = Mutex<Session?>(nil)
        f.coordinator.beforeOpenWindow = { [coordinator = f.coordinator!] session in
            opened.withLock { $0 = session }
            coordinator.lockNow()
        }
        async let ok = f.coordinator.handleLockedRequest(client: f.client)
        try await f.phoneAnswersUnlock(kr: kr, decision: .once)
        #expect(await ok == false)
        #expect(f.vault.agentWindowEndsAt == nil)
        #expect(f.vault.agentSession == nil)
        #expect(!f.hosts.mcpRunning)
        let session = try #require(opened.withLock { $0 })
        try await waitUntil { (try? await CoreThread.run { try session.vaults() }) == nil }
    }

    /// Two agents at once: one request to the phone, one answer for both.
    @Test func concurrentLockedRequestsShareOneRequest() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let kr = try await f.enroll()
        await f.lockMac()
        async let first = f.coordinator.handleLockedRequest(client: f.client)
        async let second = f.coordinator.handleLockedRequest(client: f.client)
        let phoneID = f.phone.id
        try await waitUntil { f.channel.stored().contains { $0.to == phoneID } }
        #expect(f.channel.stored().filter { $0.to == phoneID }.count == 1)
        try await f.phoneAnswersUnlock(kr: kr, decision: .once)
        let results = await [first, second]
        #expect(results == [true, true])
        #expect(f.channel.stored().filter { $0.to == phoneID }.count <= 1)
    }

    /// A window whose deadline already passed when it would open is closed at once.
    @Test func deadlineAlreadyPassedLocksImmediately() async throws {
        // The Mac's clock says two hours later than the core's: the one-hour window is over.
        let f = try await RemoteUnlockFixture.make(now: { Date().addingTimeInterval(7200) })
        defer { f.cleanUp() }
        let kr = try await f.enroll()
        await f.lockMac()
        let opened = Mutex<Session?>(nil)
        f.coordinator.beforeOpenWindow = { session in opened.withLock { $0 = session } }
        async let ok = f.coordinator.handleLockedRequest(client: f.client)
        try await f.phoneAnswersUnlock(kr: kr, decision: .once)
        #expect(await ok == false)
        #expect(f.vault.agentWindowEndsAt == nil)
        #expect(f.vault.agentSession == nil)
        let session = try #require(opened.withLock { $0 })
        try await waitUntil { (try? await CoreThread.run { try session.vaults() }) == nil }
    }

    /// A window that ends while a tool approval still waits on the phone: the approver's consumer
    /// goes and the Mac stops reading (no CloudKit poll left behind).
    @Test func windowEndWithPendingApprovalReleasesTheMailbox() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        try await f.openWindow()
        let box = f.coordinator.mailbox(for: f.macId)
        let approver = try #require(f.coordinator.windowApprover)
        let phoneID = f.phone.id
        let asked = Task { await approver.ask(approvalRequest()) }
        try await waitUntil { f.channel.stored().contains { $0.to == phoneID && $0.id.hasPrefix("request-") } }
        #expect(await box.consumerCount == 2)

        f.coordinator.lockNow()
        // Well before the request's own 60 s expiry would stop the approver anyway.
        let limit = Date().addingTimeInterval(20)
        while await box.consumerCount > 0, Date() < limit { try await Task.sleep(for: .milliseconds(20)) }
        #expect(await box.consumerCount == 0)
        #expect(await box.isReading == false)
        asked.cancel()
        _ = await asked.value
    }

    /// The 60 s limit lands while the servers start on the window: the window closes for good (the
    /// session is locked) and the next agent asks the phone again instead of being let through.
    @Test func timeoutDuringServerStartClosesTheWindow() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        await f.hosts.update({ $0.mcpEnabled = true }, session: f.vault)
        let kr = try await f.enroll()
        await f.lockMac()
        let opened = Mutex<Session?>(nil)
        f.coordinator.beforeOpenWindow = { session in opened.withLock { $0 = session } }
        f.coordinator.whileServersStart = { [coordinator = f.coordinator!] in
            coordinator.abandonPendingRequestForTesting()
        }
        async let ok = f.coordinator.handleLockedRequest(client: f.client)
        try await f.phoneAnswersUnlock(kr: kr, decision: .once)
        #expect(await ok == false)
        #expect(f.vault.agentWindowEndsAt == nil)
        #expect(f.vault.agentSession == nil)
        await f.hosts.settle()
        #expect(!f.hosts.mcpRunning)
        let session = try #require(opened.withLock { $0 })
        try await waitUntil { (try? await CoreThread.run { try session.vaults() }) == nil }

        // Not let through: the next agent goes to the phone again (refused here by the throttle).
        f.coordinator.whileServersStart = nil
        #expect(await f.coordinator.handleLockedRequest(client: f.client) == false)
        #expect(f.coordinator.lastFailure == .throttled)
    }

    /// A pairing whose phone has no active approver entry any more is erased on the next device
    /// list read, and reported like a stale enrollment; this works before `start()` read the
    /// keychain.
    @Test func phoneWithoutApproverEntryClearsCBeforeStart() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let stranger = String(repeating: "ab", count: 16)
        try f.store.save(RemoteUnlockKeyStore.Entry(mac: f.macId, phone: stranger, c: Data([1, 2, 3])))
        let fresh = f.makeCoordinator(vault: f.vault)
        try await f.vault.refreshDevices()
        try await waitUntil { @MainActor in fresh.lastFailure == .staleEnrollment }
        #expect(try f.store.load() == nil)

        // forget(phone:) before start() as well.
        try f.store.save(RemoteUnlockKeyStore.Entry(mac: f.macId, phone: stranger, c: Data([1])))
        let another = f.makeCoordinator(vault: f.vault)
        await another.forget(phone: stranger)
        #expect(try f.store.load() == nil)
    }

    /// The gate's thread blocks, never the main actor: the handler runs there and may await.
    @Test func gateBridgeAsksTheMainActorAndTimesOut() async throws {
        #expect(GateBridge.timeout >= 60)
        let hosts = DeveloperHosts(
            paths: DeveloperPaths(dataDirectory: URL(fileURLWithPath: "/tmp/op-gate"), relay: URL(fileURLWithPath: "/x")),
            defaults: UserDefaults(suiteName: "onepass.tests.gate.\(UUID().uuidString)")!, presence: FakePresence())
        let client = FfiMcpClient(id: "adhoc:1", label: "Agent", signed: false, chain: [])
        let bridge = GateBridge(owner: hosts, timeout: 600)
        func ask(_ b: GateBridge) async -> Bool {
            await withCheckedContinuation { c in Thread { c.resume(returning: b.lockedRequest(client: client)) }.start() }
        }
        // Nobody enrolled: refused.
        #expect(await ask(bridge) == false)
        hosts.setLockedRequestHandler { asked in
            try? await Task.sleep(for: .milliseconds(20))
            return asked.id == "adhoc:1"
        }
        #expect(await ask(bridge))
        // A handler that never answers in time: refused when the bridge gives up.
        hosts.setLockedRequestHandler { _ in
            try? await Task.sleep(for: .seconds(600))
            return true
        }
        #expect(await ask(GateBridge(owner: hosts, timeout: 0.3)) == false)
    }

    @Test func storedEnrollmentStaysInTheInjectedKeychain() throws {
        let keychain = InMemoryKeychain()
        let store = RemoteUnlockKeyStore(keychain: keychain)
        let entry = RemoteUnlockKeyStore.Entry(mac: "aa", phone: "bb", c: Data([1, 2, 3]))
        try store.save(entry)
        #expect(try store.load() == entry)
        #expect(RemoteUnlockKeyStore.decode(RemoteUnlockKeyStore.encode(entry)) == entry)
        try store.delete()
        #expect(try store.load() == nil)
    }
}
