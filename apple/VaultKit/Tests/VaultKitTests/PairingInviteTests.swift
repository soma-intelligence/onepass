import Foundation
import Testing

@testable import VaultKit

/// The other direction: the unlocked device shows an invite, the new device scans it and joins.
@MainActor
@Suite("Pairing from an invite")
struct PairingInviteTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    @Test func aScannedInvitePairsAndUnlocks() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        f.approverHarness.settings.displayName = "Camille Durand"
        f.approverHarness.settings.profilePhoto = Data([0x89, 0x50, 0x4E, 0x47])
        let a = PairingApproverFlow(vault: f.approver, connector: f.network)
        let inviting = Task { await a.invite(listener: f.network) }
        var code: String?
        #expect(await eventually {
            if case .inviting(let text, _) = a.state { code = text }
            return code != nil
        })
        let invite = try #require(code)
        #expect(invite.hasPrefix("OPJOIN1:"))
        #expect(pairingCodeKind(text: invite) == .invite)

        let n = PairingNewcomerFlow(
            vault: f.newcomer, mode: .personal, invite: invite, connector: f.network,
            deviceName: PairingFixture.newcomerName, deviceKind: .phone)
        n.start()
        await inviting.value
        guard case .comparing(let sas, let peer, let requested) = a.state else {
            Issue.record("approver not comparing: \(a.state)")
            return
        }
        #expect(peer.name == PairingFixture.newcomerName)
        #expect(peer.kind == .phone)
        #expect(requested == .personal)
        #expect(await eventually { n.state == .comparing(sas: sas) })

        await n.confirmCode()
        await a.approve(mode: .personal, password: testPassword)
        #expect(a.approvalError == nil)
        #expect(await eventually { n.state == .receivedFull })
        await n.importAndUnlock(password: testPassword)
        #expect(n.state == .done)
        #expect(f.newcomer.state == .unlocked)
        #expect(f.newcomer.summaries.map(\.title) == ["Messagerie exemple.fr"])
        // The new device shows the account the way the approver does.
        #expect(f.newcomerHarness.settings.displayName == "Camille Durand")
        #expect(f.newcomerHarness.settings.profilePhoto == Data([0x89, 0x50, 0x4E, 0x47]))
    }

    @Test func aConnectionWithoutTheSecretLeavesTheInviteOpen() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        let a = PairingApproverFlow(vault: f.approver, connector: f.network)
        let inviting = Task { await a.invite(listener: f.network) }
        var code: String?
        #expect(await eventually {
            if case .inviting(let text, _) = a.state { code = text }
            return code != nil
        })
        let invite = try #require(code)
        let service = try pairingServiceName(qrText: invite)

        // An intruder on the network knows the service name, not the secret.
        let stranger = try PairingNewcomer(name: "Mac inconnu", kind: .mac, mode: .personal, now: Int64(Date().timeIntervalSince1970))
        let intruder = try await f.network.connect(serviceName: service)
        try await intruder.send(stranger.hello())
        #expect(await eventually { if case .inviting = a.state { true } else { false } })

        let n = PairingNewcomerFlow(
            vault: f.newcomer, mode: .personal, invite: invite, connector: f.network,
            deviceName: PairingFixture.newcomerName, deviceKind: .phone)
        n.start()
        await inviting.value
        guard case .comparing(_, let peer, _) = a.state else {
            Issue.record("approver not comparing: \(a.state)")
            return
        }
        #expect(peer.name == PairingFixture.newcomerName)
        n.cancel()
        a.cancel()
    }

    @Test func cancellingTheInviteStopsIt() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        let a = PairingApproverFlow(vault: f.approver, connector: f.network)
        let inviting = Task { await a.invite(listener: f.network) }
        #expect(await eventually { if case .inviting = a.state { true } else { false } })
        a.cancel()
        await inviting.value
        if case .failed = a.state {} else { Issue.record("still \(a.state)") }
    }
}
