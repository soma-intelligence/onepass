import Foundation
import OnePassCore
import Synchronization
import Testing

@testable import VaultKit

/// The core's remote calls, scripted: a request blob is its 16 byte id, a response blob the JSON of
/// `FakeRemoteSession.Reply`. Like the core, it answers a request once, only from the phone it went to.
final class FakeRemoteSession: RemoteApprovalSession {
    struct Reply: Codable {
        var requestId: Data
        var from: String
        var decision: String
    }

    private struct State {
        /// Request id to the phone it went to, while it waits.
        var pending: [Data: String] = [:]
    }

    let macId: String
    let phones: [FfiApprover]
    private let state = Mutex(State())
    /// This Mac's own entry is in the list (false: a phone enrolled before the Mac registered).
    let macListed: Mutex<Bool>

    init(macId: String = "mac-1", phones: [String], macListed: Bool = true) {
        self.macId = macId
        self.phones = phones.map { FfiApprover(deviceId: $0, deviceName: "iPhone \($0)", role: .phone) }
        self.macListed = Mutex(macListed)
    }

    func thisDeviceId() -> String? { macId }

    func approvers() throws -> [FfiApprover] {
        phones + (macListed.withLock { $0 } ? [FfiApprover(deviceId: macId, deviceName: "Mac", role: .mac)] : [])
    }

    func sealRemoteRequest(keys: FfiApproverKeys, to: String, kind: FfiRemoteKind, body: FfiRequestBody) throws
        -> FfiSealedRequest
    {
        let id = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        state.withLock { $0.pending[id] = to }
        return FfiSealedRequest(
            requestId: id, to: to, expiresAt: Int64(Date().timeIntervalSince1970) + 60, blob: id)
    }

    func openRemoteResponse(keys: FfiApproverKeys, blob: Data) throws -> FfiRemoteResponse {
        let reply = try JSONDecoder().decode(Reply.self, from: blob)
        try state.withLock { s in
            guard s.pending[reply.requestId] == reply.from else { throw VaultError.integrity(kind: "remote_unknown_request") }
            s.pending.removeValue(forKey: reply.requestId)
        }
        let decision: FfiRemoteDecision = switch reply.decision {
        case "once": .once
        case "grant5m": .grant5m
        default: .denied
        }
        return FfiRemoteResponse(requestId: reply.requestId, from: reply.from, createdAt: 0, decision: decision)
    }
}

/// A phone answering through the channel.
func phoneAnswers(_ channel: InMemoryRemoteChannel, phone: String, decision: String, mac: String = "mac-1") async throws {
    let request = try #require(channel.stored().first { $0.to == phone })
    let reply = FakeRemoteSession.Reply(requestId: request.blob, from: phone, decision: decision)
    try await channel.post(RemoteMessage(
        id: UUID().uuidString, to: mac, blob: try JSONEncoder().encode(reply),
        expiresAt: Date().addingTimeInterval(60)))
}

/// Waits until `condition` holds. The deadline is generous: under a full parallel run the main
/// actor can stall for a minute, and a short wall-clock limit then fails a correct test.
func waitUntil(_ condition: @Sendable () async -> Bool) async throws {
    let deadline = Date().addingTimeInterval(100)
    while await !condition() {
        guard Date() < deadline else { Issue.record("condition never held"); return }
        try await Task.sleep(for: .milliseconds(10))
    }
}

let testApproverKeys = FfiApproverKeys(signing: Data([1]), kemSecret: Data([2]))

func approvalRequest(strong: Bool = false) -> FfiApprovalRequest {
    FfiApprovalRequest(
        surface: "mcp", client: "/usr/local/bin/claude", clientVerified: true, action: "run_with_secrets",
        details: [], targets: [FfiTarget(vault: "Personnel", item: "Github", field: "token")],
        rememberAllowed: true, strongRequired: strong, confirmCode: "kq")
}

@Suite("Remote approver", .timeLimit(.minutes(2)))
struct RemoteApproverTests {
    @Test func twoPhonesFirstValidWinsSecondLoggedLate() async throws {
        let channel = InMemoryRemoteChannel()
        let session = FakeRemoteSession(phones: ["phone-a", "phone-b"])
        let approver = RemoteApprover(
            channel: channel, session: session, keys: testApproverKeys,
            mailbox: RemoteMailbox(channel: channel, device: "mac-1"))
        let asked = Task { await approver.ask(approvalRequest()) }
        try await waitUntil { channel.stored().filter { $0.to.hasPrefix("phone-") }.count == 2 }

        // A forged answer first: refused, it does not count.
        try await channel.post(RemoteMessage(
            id: "forged", to: "mac-1", blob: Data("forged".utf8), expiresAt: Date().addingTimeInterval(60)))
        // Phone A refuses, then phone B allows: A's refusal is the first valid answer.
        try await phoneAnswers(channel, phone: "phone-a", decision: "denied")
        try await phoneAnswers(channel, phone: "phone-b", decision: "once")

        let answer = try #require(await asked.value)
        #expect(answer.decision == .deny)
        #expect(answer.approvedOn == "phone:phone-a")
        try await waitUntil { await approver.lateAnswers == ["phone-b"] }
        #expect(await approver.phonesAvailable)
        // Every request and every answer is gone from the channel. The forged one, opened by
        // nobody, stays for another reader until it expires (then purged).
        try await waitUntil { channel.stored().map(\.id) == ["forged"] }
    }

    /// A phone listed while this Mac's own approval keys are not: a request would be ignored by the
    /// phone, so the Mac registers first; without a way to register, the panel alone answers.
    @Test func unlistedMacRegistersBeforeAsking() async throws {
        let channel = InMemoryRemoteChannel()
        let session = FakeRemoteSession(phones: ["phone-a"], macListed: false)
        let unregistered = RemoteApprover(
            channel: channel, session: session, keys: testApproverKeys,
            mailbox: RemoteMailbox(channel: channel, device: "mac-1"))
        #expect(await unregistered.ask(approvalRequest()) == nil)
        #expect(await !unregistered.phonesAvailable)
        #expect(channel.stored().isEmpty)

        let registrations = Mutex(0)
        let approver = RemoteApprover(
            channel: channel, session: session, keys: testApproverKeys,
            mailbox: RemoteMailbox(channel: channel, device: "mac-1"),
            register: {
                registrations.withLock { $0 += 1 }
                session.macListed.withLock { $0 = true }
                return true
            })
        let asked = Task { await approver.ask(approvalRequest()) }
        try await waitUntil { channel.stored().contains { $0.to == "phone-a" } }
        #expect(registrations.withLock { $0 } == 1)
        try await phoneAnswers(channel, phone: "phone-a", decision: "once")
        #expect(await asked.value?.approvedOn == "phone:phone-a")

        // Registration refused: nothing sent.
        let other = InMemoryRemoteChannel()
        let refused = RemoteApprover(
            channel: other, session: FakeRemoteSession(phones: ["phone-a"], macListed: false), keys: testApproverKeys,
            mailbox: RemoteMailbox(channel: other, device: "mac-1"), register: { false })
        #expect(await refused.ask(approvalRequest()) == nil)
        #expect(other.stored().isEmpty)
    }

    @Test func lateDenialIgnoredAfterApproval() async throws {
        let channel = InMemoryRemoteChannel()
        let session = FakeRemoteSession(phones: ["phone-a", "phone-b"])
        let approver = RemoteApprover(
            channel: channel, session: session, keys: testApproverKeys,
            mailbox: RemoteMailbox(channel: channel, device: "mac-1"))
        let asked = Task { await approver.ask(approvalRequest()) }
        try await waitUntil { channel.stored().filter { $0.to.hasPrefix("phone-") }.count == 2 }
        let sent = channel.stored()

        try await phoneAnswers(channel, phone: "phone-a", decision: "grant5m")
        let answer = try #require(await asked.value)
        #expect(answer.decision == .allowForMinutes(minutes: 5))
        #expect(answer.approvedOn == "phone:phone-a")

        // Phone B had opened the request before it was withdrawn, and refuses afterwards.
        let request = try #require(sent.first { $0.to == "phone-b" })
        let reply = FakeRemoteSession.Reply(requestId: request.blob, from: "phone-b", decision: "denied")
        try await channel.post(RemoteMessage(
            id: "late", to: "mac-1", blob: try JSONEncoder().encode(reply), expiresAt: Date().addingTimeInterval(60)))
        try await waitUntil { await approver.lateAnswers == ["phone-b"] }
        try await waitUntil { channel.stored().isEmpty }
        #expect(answer.decision == .allowForMinutes(minutes: 5))
    }

    /// An approver dropped with a request still unexpired gives its consumer back: the reader stops.
    @Test func droppedApproverReleasesItsConsumer() async throws {
        let channel = InMemoryRemoteChannel()
        let box = RemoteMailbox(channel: channel, device: "mac-1")
        var approver: RemoteApprover? = RemoteApprover(
            channel: channel, session: FakeRemoteSession(phones: ["phone-a"]), keys: testApproverKeys,
            mailbox: box)
        let asked = Task { [approver] in await approver?.ask(approvalRequest()) }
        try await waitUntil { channel.stored().contains { $0.to == "phone-a" } }
        #expect(await box.consumerCount == 1)
        // The Mac answered: the request is withdrawn, but the approver keeps listening until it
        // expires (a late answer is still recognized).
        asked.cancel()
        _ = await asked.value
        #expect(await box.consumerCount == 1)
        approver = nil
        try await waitUntil { await box.consumerCount == 0 }
        #expect(await box.isReading == false)
    }

    @Test func expiredRecordsPurgedAtLaunch() async throws {
        let now = Date()
        let channel = InMemoryRemoteChannel()
        try await channel.post(RemoteMessage(id: "old", to: "mac-1", blob: Data([1]), expiresAt: now.addingTimeInterval(-1)))
        try await channel.post(RemoteMessage(id: "older", to: "phone-a", blob: Data([2]), expiresAt: now.addingTimeInterval(-3600)))
        try await channel.post(RemoteMessage(id: "live", to: "phone-a", blob: Data([3]), expiresAt: now.addingTimeInterval(30)))
        let approver = RemoteApprover(
            channel: channel, session: FakeRemoteSession(phones: ["phone-a"]), keys: testApproverKeys,
            now: { now }, mailbox: RemoteMailbox(channel: channel, device: "mac-1"))
        await approver.purgeExpired()
        #expect(channel.stored().map(\.id) == ["live"])
    }

    @Test func approverKeysStayInTheInjectedKeychain() throws {
        let keychain = InMemoryKeychain()
        let store = ApproverKeyStore(keychain: keychain)
        #expect(ApproverKeyStore.service != SystemKeychain.defaultService)
        #expect(try store.load() == nil)
        let keys = try store.loadOrCreate()
        #expect(try store.load() == keys)
        #expect(try store.loadOrCreate() == keys)
        try store.delete()
        #expect(try store.load() == nil)
    }
}
