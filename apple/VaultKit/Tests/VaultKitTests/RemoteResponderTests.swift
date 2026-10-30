import Foundation
import Security
import Synchronization
import Testing

@testable import VaultKit

/// `K_r` of each Mac in memory; `allow = false` stands for a Face ID refused or cancelled, and an
/// invalidated Mac for a key a Face ID change made unreadable (still listed, never read).
final class FakeUnlockKeyring: RemoteUnlockKeyring {
    private struct State {
        var keys: [String: Data] = [:]
        var invalidated: Set<String> = []
        var reads = 0
        var allow = true
    }
    private let state = Mutex(State())

    var keys: [String: Data] { state.withLock { $0.keys } }
    var reads: Int { state.withLock { $0.reads } }
    func allow(_ value: Bool) { state.withLock { $0.allow = value } }
    func invalidate(_ mac: String) { state.withLock { _ = $0.invalidated.insert(mac) } }

    func save(_ key: Data, for mac: String) throws {
        state.withLock {
            $0.keys[mac] = key
            $0.invalidated.remove(mac)
        }
    }

    func read(for mac: String, prompt: String) async -> KeyringRead {
        state.withLock { s in
            s.reads += 1
            guard s.allow else { return .refused }
            guard !s.invalidated.contains(mac), let key = s.keys[mac] else { return .missing }
            return .found(key)
        }
    }

    func delete(for mac: String) throws { state.withLock { _ = $0.keys.removeValue(forKey: mac) } }

    func macs() throws -> [String] { state.withLock { Array($0.keys.keys) } }
}

/// The Face ID gate of the current biometric set: `invalidate()` stands for a face or appearance
/// added (the gate is unreadable until armed again), `answer(false)` for a cancelled Face ID.
final class FakeFaceIDGate: FaceIDGate {
    private struct State {
        var armed = true
        var answer = true
        var checks = 0
    }
    private let state = Mutex(State())

    var checks: Int { state.withLock { $0.checks } }
    var armed: Bool { state.withLock { $0.armed } }
    func invalidate() { state.withLock { $0.armed = false } }
    func answer(_ value: Bool) { state.withLock { $0.answer = value } }

    func check(prompt: String) async -> FaceIDCheck {
        state.withLock { s in
            s.checks += 1
            guard s.armed else { return .invalidated }
            return s.answer ? .confirmed : .refused
        }
    }

    func arm() throws { state.withLock { $0.armed = true } }
    func disarm() throws { state.withLock { $0.armed = false } }
}

/// The phone's clock as the responder reads it: the real one plus `offset` seconds.
final class PhoneClock: Sendable {
    private let offset = Mutex<TimeInterval>(0)
    func set(_ seconds: TimeInterval) { offset.withLock { $0 = seconds } }
    var now: @Sendable () -> Date { { Date().addingTimeInterval(self.offset.withLock { $0 }) } }
}

/// The iPhone side of the remote approval (agent-ready spec 5 and 6): requests from the Mac of the
/// fixture, answered through the real core, with fake Face ID and keychain only.
@MainActor
@Suite("Remote responder", .timeLimit(.minutes(5)))
struct RemoteResponderTests {
    struct Phone {
        let responder: RemoteResponder
        let presence: FakePresence
        let keyring: FakeUnlockKeyring
        let clock: PhoneClock
    }

    private func phone(_ f: RemoteUnlockFixture, presence gate: (any PresenceChecker)? = nil) async -> Phone {
        let presence = FakePresence()
        let keyring = FakeUnlockKeyring()
        let clock = PhoneClock()
        let responder = RemoteResponder(
            channel: f.channel, session: f.phone.session, keys: f.phone.keys, presence: gate ?? presence,
            keyring: keyring, now: clock.now)
        await responder.start()
        return Phone(responder: responder, presence: presence, keyring: keyring, clock: clock)
    }

    private func macKeys(_ f: RemoteUnlockFixture) throws -> FfiApproverKeys {
        try #require(try ApproverKeyStore(keychain: f.macKeychain).load())
    }

    /// The Mac asks the phone to approve an agent request, as `RemoteApprover` does.
    @discardableResult
    private func macAsks(
        _ f: RemoteUnlockFixture, strong: Bool = true, remember: Bool = true
    ) async throws -> FfiSealedRequest {
        let core = try #require(f.vault.coreSession)
        let keys = try macKeys(f)
        let phoneID = f.phone.id
        var request = approvalRequest(strong: strong)
        request.rememberAllowed = remember
        let body = RemoteApprover.body(of: request)
        let sealed = try await CoreThread.run {
            try core.sealRemoteRequest(keys: keys, to: phoneID, kind: .approve, body: body)
        }
        try await f.channel.post(RemoteMessage(
            id: "request-" + RemoteApprover.hex(sealed.requestId), to: sealed.to, blob: sealed.blob,
            expiresAt: Date(timeIntervalSince1970: TimeInterval(sealed.expiresAt))))
        return sealed
    }

    private func toMac(_ f: RemoteUnlockFixture) -> [RemoteMessage] {
        f.channel.stored().filter { $0.to == f.macId }
    }

    private func firstPending(_ p: Phone, kind: FfiRemoteKind) async throws -> OpenedRequest {
        try await waitUntil { await p.responder.pending().contains { $0.kind == kind } }
        return try #require(await p.responder.pending().first { $0.kind == kind })
    }

    /// Enrolled from the Mac, accepted on the phone after Face ID: `K_r` is in the phone's keyring.
    private func enroll(_ f: RemoteUnlockFixture, _ p: Phone) async throws -> String {
        let code = try await f.coordinator.enroll(phone: f.phone.id)
        let pair = try await firstPending(p, kind: .pair)
        try await p.responder.acceptEnrollment(pair.id)
        return code
    }

    @Test func answerRequiresPresence() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let p = await phone(f)
        defer { Task { await p.responder.stop() } }
        try await macAsks(f, strong: true)

        let request = try await firstPending(p, kind: .approve)
        #expect(request.mac == f.macId)
        #expect(!request.macName.isEmpty)
        #expect(request.body.strongRequired)
        #expect(request.body.confirmCode == "kq")
        #expect(request.body.targets == ["Personnel / Github / token"])
        // Opened: the record left the transport.
        try await waitUntil { f.channel.stored().allSatisfy { $0.to != f.phone.id } }

        try await p.responder.answer(request.id, decision: .once)
        // Face ID only (biometrics, never the passcode), before anything left the phone.
        #expect(p.presence.biometricPrompts == 1)
        #expect(p.presence.prompts == 0)
        #expect(await p.responder.pending().isEmpty)

        let answer = try #require(toMac(f).first)
        let core = try #require(f.vault.coreSession)
        let keys = try macKeys(f)
        let response = try await CoreThread.run { try core.openRemoteResponse(keys: keys, blob: answer.blob) }
        #expect(response.decision == .once)
        #expect(response.from == f.phone.id)
    }

    @Test func deniedPresenceSendsNothing() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let p = await phone(f)
        defer { Task { await p.responder.stop() } }
        try await macAsks(f, strong: false)
        let request = try await firstPending(p, kind: .approve)

        p.presence.answer(false)
        for decision in [FfiRemoteDecision.once, .denied, .grant5m] {
            await #expect(throws: RemoteResponderError.presenceRequired) {
                try await p.responder.answer(request.id, decision: decision)
            }
        }
        #expect(p.presence.biometricPrompts == 3)
        #expect(toMac(f).isEmpty)
        // Still there: the owner may try again.
        #expect(await p.responder.pending().map(\.id) == [request.id])

        p.presence.answer(true)
        try await p.responder.answer(request.id, decision: .denied)
        #expect(toMac(f).count == 1)
    }

    @Test func unlockAnswerCarriesSealedKey() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let p = await phone(f)
        defer { Task { await p.responder.stop() } }
        _ = try await enroll(f, p)
        await f.lockMac()

        async let opened = f.coordinator.handleLockedRequest(client: f.client)
        let request = try await firstPending(p, kind: .approveAndUnlock)
        // First step of two: who asks and for how long, no item.
        #expect(request.isUnlock)
        #expect(request.body.client == "Agent Exemple")
        #expect(request.body.clientVerified)
        #expect(request.body.targets.isEmpty)
        #expect(request.body.windowMinutes == 60)

        // Face ID refused: `K_r` stays in the keychain, nothing goes to the Mac.
        p.keyring.allow(false)
        await #expect(throws: RemoteResponderError.presenceRequired) {
            try await p.responder.answer(request.id, decision: .once)
        }
        #expect(toMac(f).isEmpty)

        p.keyring.allow(true)
        try await p.responder.answer(request.id, decision: .once)
        #expect(p.keyring.reads == 2)
        // The Mac opened `C` with the `K_r` the answer carried: an agents-only window.
        #expect(await opened)
        #expect(try #require(f.vault.agentSession).isAgentOnly())
        #expect(f.vault.state == .locked)
    }

    @Test func enrollmentStoresKeyThisDeviceOnly() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let p = await phone(f)
        defer { Task { await p.responder.stop() } }
        let code = try await f.coordinator.enroll(phone: f.phone.id)
        let pair = try await firstPending(p, kind: .pair)
        #expect(pair.isPairing)
        #expect(pair.mac == f.macId)
        // The phone shows the two letters the Mac shows.
        #expect(pair.body.confirmCode == code)

        // No Face ID, no key.
        p.presence.answer(false)
        await #expect(throws: RemoteResponderError.presenceRequired) {
            try await p.responder.acceptEnrollment(pair.id)
        }
        #expect(p.keyring.keys.isEmpty)

        p.presence.answer(true)
        try await p.responder.acceptEnrollment(pair.id)
        #expect(p.presence.biometricPrompts == 2)
        #expect(p.keyring.keys[f.macId]?.count == 32)
        #expect(await p.responder.pending().isEmpty)
        #expect(await p.responder.enrolledMacs() == [f.macId])

        // The system keyring: this device only, never synced, Face ID of the current set.
        #expect(SystemRemoteUnlockKeyring.protection as String == kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String)
        #expect(SystemRemoteUnlockKeyring.accessFlags == .biometryCurrentSet)
        let attributes = try SystemRemoteUnlockKeyring.itemAttributes(for: f.macId)
        #expect(attributes[kSecAttrAccessControl as String] != nil)
        #expect(attributes[kSecAttrSynchronizable as String] as? Bool == false)
        #expect(attributes[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(attributes[kSecAttrAccessible as String] == nil)
        #expect(attributes[kSecAttrAccount as String] as? String == "kr." + f.macId)
    }

    @Test func expiredRequestHiddenWithClockHint() async throws {
        // The fake server stamps each record with its own clock.
        let server = PhoneClock()
        let f = try await RemoteUnlockFixture.make(channel: InMemoryRemoteChannel(now: server.now))
        defer { f.cleanUp() }
        let p = await phone(f)
        defer { Task { await p.responder.stop() } }

        // Long expired on every clock (the server stored it as late as the phone reads it, a blob
        // put back long after): hidden, erased, no hint.
        server.set(600)
        p.clock.set(600)
        try await macAsks(f)
        try await waitUntil { f.channel.stored().allSatisfy { $0.to != f.phone.id } }
        #expect(await p.responder.pending().isEmpty)
        #expect(await !p.responder.clockLooksWrong)

        // Phone ten minutes ahead: the server stored it when the Mac made it, only the phone calls
        // it expired. Hidden, with the hint.
        server.set(0)
        try await macAsks(f)
        try await waitUntil { await p.responder.clockLooksWrong }
        #expect(await p.responder.pending().isEmpty)
        try await waitUntil { f.channel.stored().allSatisfy { $0.to != f.phone.id } }
        #expect(RemoteResponderError.clockSkew.message.contains("Vérifie l'heure de ton iPhone"))

        // Within the tolerance (100 s ahead): shown, and the hint goes.
        p.clock.set(100)
        try await macAsks(f)
        _ = try await firstPending(p, kind: .approve)
        #expect(await !p.responder.clockLooksWrong)

        // Phone ten minutes behind: dated in its future. Hidden (only the earlier one stays), with
        // the hint.
        p.clock.set(-600)
        try await macAsks(f)
        try await waitUntil { await p.responder.clockLooksWrong }
        #expect(await p.responder.pending().count == 1)

        // Shown, then expired on screen: hidden from the list, refused if answered.
        p.clock.set(100)
        try await macAsks(f)
        try await waitUntil { await p.responder.pending().count == 2 }
        let shown = try #require(await p.responder.pending().first)
        p.clock.set(400)
        #expect(await p.responder.pending().isEmpty)
        await #expect(throws: RemoteResponderError.expired) {
            try await p.responder.answer(shown.id, decision: .once)
        }
        #expect(p.presence.biometricPrompts == 0)
        #expect(toMac(f).isEmpty)
    }

    @Test func forgetDeletesKeyAndNotifiesMac() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let p = await phone(f)
        defer { Task { await p.responder.stop() } }
        _ = try await enroll(f, p)
        let keys = try macKeys(f)
        let macPath = f.macPath
        let phoneID = f.phone.id

        try await p.responder.forget(mac: f.macId)
        #expect(p.keyring.keys.isEmpty)
        #expect(await p.responder.enrolledMacs().isEmpty)
        let forget = try #require(toMac(f).first)
        let notice = try await CoreThread.run {
            try RemoteUnlocker(dbPath: macPath, macKeys: keys).openRemoteNotice(blob: forget.blob, enrolledPhone: phoneID)
        }
        #expect(notice.kind == .forgetUnlock)
        #expect(notice.from == phoneID)
        await f.channel.delete(forget.id)

        // "Verrouiller maintenant": a signed Lock to that Mac.
        try await p.responder.lockNow(mac: f.macId)
        let lock = try #require(toMac(f).first)
        let lockNotice = try await CoreThread.run {
            try RemoteUnlocker(dbPath: macPath, macKeys: keys).openRemoteNotice(blob: lock.blob, enrolledPhone: phoneID)
        }
        #expect(lockNotice.kind == .lock)
    }

    @Test func revokedMacClearsKey() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let p = await phone(f)
        defer { Task { await p.responder.stop() } }
        _ = try await enroll(f, p)
        // A key for a Mac that is not (or no longer) an approver of the account.
        let stranger = String(repeating: "ab", count: 16)
        try p.keyring.save(Data(repeating: 7, count: 32), for: stranger)

        // The enrolled Mac is active: its key stays; the stranger's goes.
        await p.responder.dropRevokedMacs()
        #expect(Set(p.keyring.keys.keys) == [f.macId])

        // Revoked in the device list: its key goes too.
        let phoneSession = f.phone.session
        let macID = f.macId
        try await CoreThread.run { try phoneSession.revokeDevice(id: macID) }
        await p.responder.dropRevokedMacs()
        #expect(p.keyring.keys.isEmpty)
    }

    @Test func faceIDChangeOffersReset() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let gate = FakeFaceIDGate()
        let p = await phone(f, presence: gate)
        defer { Task { await p.responder.stop() } }
        try await macAsks(f, strong: true)
        let request = try await firstPending(p, kind: .approve)

        // A face added: the gate is unreadable. A refusal too fails, and says why.
        gate.invalidate()
        for decision in [FfiRemoteDecision.denied, .once] {
            await #expect(throws: RemoteResponderError.faceIDChanged) {
                try await p.responder.answer(request.id, decision: decision)
            }
        }
        #expect(await p.responder.faceIDNeedsReset)
        #expect(toMac(f).isEmpty)

        // "Réactiver Face ID" with Face ID cancelled: no gate is left armed.
        gate.answer(false)
        await #expect(throws: RemoteResponderError.presenceRequired) {
            try await p.responder.reArmFaceID()
        }
        #expect(!gate.armed)
        #expect(await p.responder.faceIDNeedsReset)

        // With Face ID of the current set: armed again, and the answer goes.
        gate.answer(true)
        try await p.responder.reArmFaceID()
        #expect(gate.armed)
        #expect(await !p.responder.faceIDNeedsReset)
        try await p.responder.answer(request.id, decision: .denied)
        #expect(toMac(f).count == 1)
    }

    @Test func invalidatedUnlockKeyNeedsReenrollment() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let gate = FakeFaceIDGate()
        let p = await phone(f, presence: gate)
        defer { Task { await p.responder.stop() } }
        _ = try await enroll(f, p)
        await f.lockMac()

        async let opened = f.coordinator.handleLockedRequest(client: f.client)
        let request = try await firstPending(p, kind: .approveAndUnlock)
        // No "5 min" on an unlock.
        await #expect(throws: RemoteResponderError.notAllowed) {
            try await p.responder.answer(request.id, decision: .grant5m)
        }

        // A Face ID change made `K_r` unreadable: enroll again from the Mac, not "try Face ID again".
        p.keyring.invalidate(f.macId)
        await #expect(throws: RemoteResponderError.notEnrolled) {
            try await p.responder.answer(request.id, decision: .once)
        }
        #expect(p.keyring.keys.isEmpty)
        #expect(await p.responder.enrolledMacs().isEmpty)
        #expect(toMac(f).isEmpty)

        // A refusal still goes, behind the gate.
        let checks = gate.checks
        try await p.responder.answer(request.id, decision: .denied)
        #expect(gate.checks == checks + 1)
        #expect(await !opened)
        #expect(f.vault.agentSession == nil)
    }

    @Test func grantMinutesRefusedWhenNotAllowed() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let p = await phone(f)
        defer { Task { await p.responder.stop() } }
        try await macAsks(f, remember: false)
        let request = try await firstPending(p, kind: .approve)
        #expect(!request.mayGrantMinutes)

        await #expect(throws: RemoteResponderError.notAllowed) {
            try await p.responder.answer(request.id, decision: .grant5m)
        }
        // Refused before Face ID: nothing asked, nothing sent.
        #expect(p.presence.biometricPrompts == 0)
        #expect(toMac(f).isEmpty)
        try await p.responder.answer(request.id, decision: .once)
        #expect(toMac(f).count == 1)
    }

    @Test func pairRefusedSendsNothing() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let p = await phone(f)
        defer { Task { await p.responder.stop() } }
        try await f.coordinator.enroll(phone: f.phone.id)
        let pair = try await firstPending(p, kind: .pair)

        // A pairing is not answered as a request.
        await #expect(throws: RemoteResponderError.notAllowed) {
            try await p.responder.answer(pair.id, decision: .once)
        }
        await p.responder.dismiss(pair.id)
        #expect(await p.responder.pending().isEmpty)
        #expect(p.keyring.keys.isEmpty)
        #expect(p.presence.biometricPrompts == 0)
        #expect(toMac(f).isEmpty)
        await #expect(throws: RemoteResponderError.unknownRequest) {
            try await p.responder.acceptEnrollment(pair.id)
        }
    }
}
