import Foundation
import Testing

@testable import VaultKit

@MainActor
@Suite("Public session")
struct PublicSessionTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    /// Up to a running guest session lending the fixture's login for `minutes`.
    private func start(_ f: PairingFixture, minutes: UInt32 = 15) async throws
        -> (PublicSession, PairingApproverFlow, String)
    {
        let (n, a, service) = try await f.compare(mode: .public)
        await n.confirmCode()
        let ref = FfiItemRef(vaultId: f.login.vaultId, itemId: f.login.id)
        await a.approvePublic(items: [ref], minutes: minutes, password: testPassword)
        guard case .publicRunning(let journal, _) = a.state else {
            Issue.record("approver not running: \(a.state)")
            throw CancellationError()
        }
        #expect(journal.isEmpty)
        var session: PublicSession?
        #expect(await eventually {
            if case .receivedPublic(let s) = n.state { session = s }
            return session != nil
        })
        let guest = try #require(session)
        #expect(guest.isActive)
        #expect(guest.items.map(\.id) == [f.login.id])
        #expect(guest.items[0].passwordHistoryCount == 0)
        // Nothing reached the guest's disk.
        #expect(!FileManager.default.fileExists(atPath: f.newcomerPath))
        return (guest, a, service)
    }

    @Test func publicSessionExpiresAndEnds() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        let (guest, a, _) = try await start(f)
        let clock = f.newcomerHarness.clock
        let pasteboard = f.newcomerHarness.pasteboard
        #expect(guest.remaining > 14 * 60 && guest.remaining <= 15 * 60)

        // Viewing and copying reach the approver's journal (the label, never the value).
        guest.viewed(itemID: f.login.id)
        guest.copy("motdepasse-fictif", label: "Mot de passe", itemID: f.login.id)
        #expect(pasteboard.snapshot.contents == "motdepasse-fictif")
        #expect(pasteboard.snapshot.concealed)
        #expect(await eventually {
            if case .publicRunning(let journal, _) = a.state { journal.count == 2 } else { false }
        })
        if case .publicRunning(let journal, _) = a.state {
            #expect(journal.map(\.action) == [.opened, .copied(label: "Mot de passe")])
            #expect(journal.allSatisfy { $0.itemID == f.login.id && $0.title == "Messagerie exemple.fr" })
        }

        // The clipboard clears after 30 s.
        clock.advance(31)
        guest.tick()
        #expect(pasteboard.snapshot.contents == nil)
        #expect(guest.isActive)

        // Expiry ends it on both sides.
        for _ in 0..<4 {
            clock.advance(240)
            guest.noteActivity()
            guest.tick()
        }
        #expect(guest.endReason == .expired)
        #expect(guest.items.isEmpty)
        f.approverHarness.clock.advance(15 * 60)
        a.tick()
        #expect(a.state == .done)

        // A second session ends after 5 minutes without activity.
        let (idle, idleApprover, _) = try await start(f)
        clock.advance(299)
        idle.tick()
        #expect(idle.isActive)
        clock.advance(2)
        idle.tick()
        #expect(idle.endReason == .inactivity)
        #expect(await eventually { idleApprover.state == .done })

        // A third one ends from the guest ("Terminer"): the approver is told.
        let (ended, endedApprover, _) = try await start(f)
        ended.end()
        #expect(ended.endReason == .endedHere)
        #expect(await eventually { endedApprover.state == .done })

        // And a fourth from the approver.
        let (owned, ownedApprover, _) = try await start(f)
        await ownedApprover.endPublicSession()
        #expect(ownedApprover.state == .done)
        #expect(await eventually { owned.endReason == .endedByOwner })
        #expect(owned.items.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: f.newcomerPath))
    }

    @Test func publicSessionEndsOnTransportClose() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        let (guest, a, service) = try await start(f)
        f.network.disconnect(service: service)
        #expect(await eventually { guest.endReason == .connectionLost })
        #expect(guest.items.isEmpty)
        #expect(await eventually { a.state == .done })
    }
}
