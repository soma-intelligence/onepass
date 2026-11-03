import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// The fast KDF of the test framework, usable off the main actor.
let sharingFastKdf = FfiKdfParams(mKib: 8192, t: 1, p: 1)

/// An account with v2 device keys (a software PQ half from the test framework), for the sharing
/// flows. Synthetic data only.
final class SharingPerson: @unchecked Sendable {
    let dir: URL
    let path: String
    let session: Session
    let secretKey: String
    let classical: Data
    let pq: any FfiPqDeviceHalf
    let keychain = InMemoryKeychain()
    let name: String

    init(_ name: String) throws {
        self.name = name
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-share-\(name)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        path = dir.appendingPathComponent("v.db").path
        classical = try generateClassicalDeviceKeys()
        pq = try testSoftwarePqHalf()
        let created = try createAccountV2(
            dbPath: path, password: testPassword, kdf: sharingFastKdf, classical: classical, pq: pq,
            name: "iPhone de \(name)", kind: .phone, mode: .personal)
        session = created.session
        secretKey = created.secretKey
    }

    var keys: any DeviceKeySource { FixedKeys(pair: DeviceKeyPair(classical: classical, pq: pq)) }
    var accountID: String { session.accountId() }

    func cleanUp() { try? FileManager.default.removeItem(at: dir) }
}

struct FixedKeys: DeviceKeySource {
    let pair: DeviceKeyPair
    func deviceKeys() throws -> DeviceKeyPair { pair }
}

/// The creator's offer without a server (`test_contact_zone_offer`).
struct OfflineZoneCreator: ContactZoneCreating {
    func offer(for peerCard: Data, session: Session) async throws -> Data {
        let now = Int64(Date().timeIntervalSince1970)
        return try await CoreThread.run { try testContactZoneOffer(session: session, peerCard: peerCard, now: now) }
    }
}

/// Polls `condition` on the main actor.
@MainActor
func waitFor(_ condition: @MainActor () -> Bool, timeout: Duration = .seconds(180)) async throws {
    let deadline = ContinuousClock.now + timeout
    while !condition() {
        if ContinuousClock.now > deadline {
            Issue.record("condition never met")
            return
        }
        try await Task.sleep(for: .milliseconds(20))
    }
}

/// Sharing plan 4, Task 7: the contact verification flows (sharing spec 5.3.1, 5.3.2, decision 1).
@MainActor
@Suite(.serialized) struct ContactFlowTests {
    private let hosted = URL(string: "https://soma.exemple.fr/functions/v1/mailbox")!

    private func flows(_ a: SharingPerson, _ b: SharingPerson) -> (ContactVerificationFlow, ContactVerificationFlow) {
        let service = InMemoryPairingNetwork().service(LocalNetworkPairingTransport.contactServiceType)
        func flow(_ p: SharingPerson) -> ContactVerificationFlow {
            ContactVerificationFlow(
                session: p.session, myName: p.name, keys: p.keys, listener: service, connector: service,
                creator: OfflineZoneCreator())
        }
        return (flow(a), flow(b))
    }

    @Test func faceToFaceFlowReachesVerified() async throws {
        let (alice, bob) = (try SharingPerson("Alice"), try SharingPerson("Bob"))
        defer { alice.cleanUp(); bob.cleanUp() }
        let (shower, scanner) = flows(alice, bob)
        shower.showCode()
        try await waitFor { if case .showingQR = shower.state { true } else { false } }
        guard case .showingQR(let qr) = shower.state else { return }
        scanner.scan(qrText: qr)
        try await waitFor {
            if case .comparing = shower.state, case .comparing = scanner.state { true } else { false }
        }
        #expect(shower.state == scanner.state)
        shower.confirm()
        scanner.confirm()
        try await waitFor {
            if case .done = shower.state, case .done = scanner.state { true } else { false }
        }
        guard case .done(let bobSeen) = shower.state, case .done(let aliceSeen) = scanner.state else {
            Issue.record("states: \(shower.state) / \(scanner.state)")
            return
        }
        #expect(bobSeen.level == .verified)
        #expect(aliceSeen.level == .verified)
        #expect(bobSeen.nameLocal == "Bob")
        #expect(aliceSeen.nameLocal == "Alice")
        #expect(try alice.session.contacts().map(\.accountId) == [bob.accountID])
        #expect(try bob.session.contacts().map(\.accountId) == [alice.accountID])
    }

    @Test func sasMismatchAbortsWithoutPin() async throws {
        let (alice, bob) = (try SharingPerson("Alice"), try SharingPerson("Bob"))
        defer { alice.cleanUp(); bob.cleanUp() }
        let (shower, scanner) = flows(alice, bob)
        shower.showCode()
        try await waitFor { if case .showingQR = shower.state { true } else { false } }
        guard case .showingQR(let qr) = shower.state else { return }
        scanner.scan(qrText: qr)
        try await waitFor { if case .comparing = scanner.state { true } else { false } }
        scanner.reject()
        #expect(scanner.state == .failed(.codeRejected))
        // Alice confirms on her side: the connection is gone, nothing is pinned.
        try await waitFor { if case .comparing = shower.state { true } else { false } }
        shower.confirm()
        try await waitFor { if case .failed = shower.state { true } else { false } }
        #expect(try alice.session.contacts().isEmpty)
        #expect(try bob.session.contacts().isEmpty)
    }

    private func inviteFlow(_ p: SharingPerson, session: Session?, drops: InMemoryInviteDrops) -> ContactInviteFlow {
        ContactInviteFlow(
            session: session, myName: p.name, keychain: p.keychain, drops: drops, creator: OfflineZoneCreator(),
            hosted: hosted, pollInterval: .milliseconds(20))
    }

    @Test func inviteFlowReachesLinkThenVerified() async throws {
        let (alice, bob) = (try SharingPerson("Alice"), try SharingPerson("Bob"))
        defer { alice.cleanUp(); bob.cleanUp() }
        let drops = InMemoryInviteDrops()
        let inviter = inviteFlow(alice, session: alice.session, drops: drops)
        let invitee = inviteFlow(bob, session: bob.session, drops: drops)
        inviter.createInvite()
        try await waitFor { if case .sharing = inviter.state { true } else { false } }
        guard case .sharing(let link, _) = inviter.state else { return }
        invitee.open(link: link)
        try await waitFor {
            if case .done = inviter.state, case .done = invitee.state { true } else { false }
        }
        guard case .done(let bobSeen) = inviter.state, case .done(let aliceSeen) = invitee.state else { return }
        // Decision 1: a link gives Link (Read only) until the safety numbers are compared.
        #expect(bobSeen.level == .link)
        #expect(aliceSeen.level == .link)
        #expect(bobSeen.safetyNumber == aliceSeen.safetyNumber)
        let now = Int64(Date().timeIntervalSince1970)
        try alice.session.confirmSafetyNumber(accountId: bob.accountID, shown: bobSeen.safetyNumber, now: now)
        try bob.session.confirmSafetyNumber(accountId: alice.accountID, shown: aliceSeen.safetyNumber, now: now)
        #expect(try alice.session.contacts().first?.level == .verified)
        #expect(try bob.session.contacts().first?.level == .verified)
        // The drops are gone and the pending secret left the Keychain.
        #expect(bob.keychain.keys.isEmpty)
    }

    @Test func contactLinkSurvivesUnlock() async throws {
        let (alice, bob) = (try SharingPerson("Alice"), try SharingPerson("Bob"))
        defer { alice.cleanUp(); bob.cleanUp() }
        let drops = InMemoryInviteDrops()
        let inviter = inviteFlow(alice, session: alice.session, drops: drops)
        inviter.createInvite()
        try await waitFor { if case .sharing = inviter.state { true } else { false } }
        guard case .sharing(let link, _) = inviter.state else { return }
        // Bob's app is locked when the link opens it.
        let invitee = inviteFlow(bob, session: nil, drops: drops)
        invitee.open(link: link)
        #expect(invitee.state == .waitingForUnlock)
        #expect(try bob.keychain.read(ContactInviteFlow.linkKey) == Data(link.utf8))
        invitee.unlocked(bob.session)
        #expect(try bob.keychain.read(ContactInviteFlow.linkKey) == nil)
        try await waitFor {
            if case .done = inviter.state, case .done = invitee.state { true } else { false }
        }
    }

    @Test func pairingServiceNeverAnswersContact() async throws {
        let network = InMemoryPairingNetwork()
        let contact = network.service(LocalNetworkPairingTransport.contactServiceType)
        let pairing = network.service(LocalNetworkPairingTransport.serviceType)
        let reached = Mutex(false)
        let listening = Task {
            _ = try await contact.listen(serviceName: "abcd")
            reached.withLock { $0 = true }
        }
        _ = try await pairing.connect(serviceName: "abcd")
        try await Task.sleep(for: .milliseconds(200))
        #expect(reached.withLock { $0 } == false)
        // The reverse: a pairing listener is not reached by a contact connector.
        let pairingListening = Task {
            _ = try await pairing.listen(serviceName: "efgh")
            reached.withLock { $0 = true }
        }
        _ = try await contact.connect(serviceName: "efgh")
        try await Task.sleep(for: .milliseconds(200))
        #expect(reached.withLock { $0 } == false)
        listening.cancel()
        pairingListening.cancel()
        // Same service type: it connects.
        let same = Task { try await contact.listen(serviceName: "ijkl") }
        _ = try await contact.connect(serviceName: "ijkl")
        _ = try await same.value
        #expect(LocalNetworkPairingTransport.contactServiceType == "_onepass-contact._tcp")
    }
}
