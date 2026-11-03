import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// Sharing plan 4, Task 6: the drops of a remote contact invitation and the pair's mailbox made
/// before anything is pinned (sharing spec 13.5, 13.9, decision 16).
@Suite struct ContactZoneTests {
    private let hosted = URL(string: "https://soma.exemple.fr/functions/v1/mailbox")!
    private let rdv = Data(repeating: 0x5A, count: 16)

    private func session() throws -> (Session, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-contact-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let created = try createAccountWithKdf(
            dbPath: dir.appendingPathComponent("v.db").path, password: testPassword, kdf: sharingFastKdf)
        return (created.session, dir)
    }

    @Test func inviteDropRoundTrip() async throws {
        let drops = InMemoryInviteDrops()
        #expect(try await drops.get(rdv: rdv, part: .reply, server: hosted) == nil)
        try await drops.put(rdv: rdv, part: .reply, bytes: Data("réponse".utf8), server: hosted)
        #expect(try await drops.get(rdv: rdv, part: .reply, server: hosted) == Data("réponse".utf8))
        // The two halves never mix.
        #expect(try await drops.get(rdv: rdv, part: .answer, server: hosted) == nil)
        try await drops.delete(rdv: rdv, part: .reply, server: hosted)
        #expect(try await drops.get(rdv: rdv, part: .reply, server: hosted) == nil)
    }

    @Test func dropWrittenOnce() async throws {
        let drops = InMemoryInviteDrops()
        try await drops.put(rdv: rdv, part: .answer, bytes: Data([1]), server: hosted)
        // A retry of the same bytes passes; other bytes are refused.
        try await drops.put(rdv: rdv, part: .answer, bytes: Data([1]), server: hosted)
        await #expect(throws: OnePassError.Conflict) {
            try await drops.put(rdv: rdv, part: .answer, bytes: Data([2]), server: hosted)
        }
    }

    @Test func linkWithHostUsesThatServer() {
        #expect(InviteServer.url(forLink: "onepass://contact/boite.exemple.fr#ABCDEF", hosted: hosted)
            == URL(string: "https://boite.exemple.fr/functions/v1/mailbox"))
        #expect(InviteServer.url(forLink: "onepass://contact#ABCDEF", hosted: hosted) == hosted)
        #expect(InviteServer.url(forLink: "https://ailleurs.fr/c#ABCDEF", hosted: hosted) == hosted)
        // A host that would not pass as a server falls back to the Soma instance.
        #expect(InviteServer.url(forLink: "onepass://contact/a b#ABCDEF", hosted: hosted) == hosted)
        #expect(InviteServer.linkHost(for: hosted, hosted: hosted) == nil)
        #expect(InviteServer.linkHost(for: URL(string: "https://boite.exemple.fr/functions/v1/mailbox")!, hosted: hosted)
            == "boite.exemple.fr")
    }

    private struct FakeCreator: ContactZoneCreating {
        let log: CallLog
        let fails: Bool
        func offer(for peerCard: Data, session: Session) async throws -> Data {
            log.append("offer")
            if fails { throw ContactZoneError.offline }
            return Data([9])
        }
    }

    @Test func contactZoneCreatedBeforePin() async throws {
        let (session, dir) = try session()
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = CallLog()
        let offer = try await ContactZoneStep.offerThenPin(
            creator: FakeCreator(log: log, fails: false), peerCard: Data([1]), session: session
        ) { offer in
            log.append("pin")
            return offer
        }
        #expect(offer == Data([9]))
        #expect(log.all == ["offer", "pin"])
    }

    @Test func offlineCreatorPinsNothing() async throws {
        let (session, dir) = try session()
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = CallLog()
        await #expect(throws: ContactZoneError.offline) {
            try await ContactZoneStep.offerThenPin(
                creator: FakeCreator(log: log, fails: true), peerCard: Data([1]), session: session
            ) { _ in log.append("pin") }
        }
        #expect(log.all == ["offer"])
        #expect(ContactZoneError.offline.message(name: "Camille").contains("Camille"))
        // The real creator with no reachable server says offline too, and pins nothing.
        let handle = ZoneSyncHandle(
            seeds: ZoneSeedKeychain(keychain: InMemoryKeychain()), defaultBaseUrl: "https://127.0.0.1:9/functions/v1/mailbox",
            extraCaPem: nil)
        await #expect(throws: (any Error).self) {
            _ = try await ContactZoneCreator(handle: handle).offer(for: Data([1, 2, 3]), session: session)
        }
        #expect(try session.contacts().isEmpty)
    }

    @Test func dropIdsNeverLogged() async throws {
        let lines = Mutex<[String]>([])
        let drops = ContactInviteDrops(log: { line in lines.withLock { $0.append(line) } })
        let server = URL(string: "https://127.0.0.1:9/functions/v1/mailbox")!
        _ = try? await drops.put(rdv: rdv, part: .reply, bytes: Data([1, 2]), server: server)
        _ = try? await drops.get(rdv: rdv, part: .answer, server: server)
        let hex = rdv.map { String(format: "%02x", $0) }.joined()
        let logged = lines.withLock { $0 }
        #expect(!logged.isEmpty)
        #expect(logged.allSatisfy { !$0.lowercased().contains(hex) && !$0.contains(rdv.base64EncodedString()) })
    }
}
