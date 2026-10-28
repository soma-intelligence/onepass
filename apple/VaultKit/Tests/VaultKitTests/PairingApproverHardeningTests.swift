import Foundation
import Testing

@testable import VaultKit

/// The approver after the security review of milestone 2b: no grant once cancelled, one approval at
/// a time, a bounded wait for the new device, a bounded public journal, and biometrics only (never
/// the device passcode) as the fresh presence of ruling A8.
@MainActor
@Suite("Pairing approver hardening")
struct PairingApproverHardeningTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    /// "Annuler" while Face ID is on screen: nothing is listed, nothing is sent, and the approver
    /// never says "Appareil ajouté" (M1).
    @Test func cancelDuringPresenceGrantsNothing() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        try await f.approver.enrollBiometrics(password: testPassword)
        let (n, a, service) = try await f.compare(mode: .personal)
        await n.confirmCode()
        let presence = f.approverHarness.presence
        presence.hold()
        let approving = Task { await a.approve(mode: .personal) }
        #expect(await eventually { presence.pending == 1 })
        a.cancel()
        presence.release()
        await approving.value
        #expect(a.state == .failed(.codeRejected))
        #expect(f.network.frames(service: service, from: .connector).count == 1, "only the key exchange left")
        try await f.approver.refreshDevices()
        #expect(f.approver.devices.count == 1)
        #expect(n.state != .receivedFull)
    }

    /// A second "Les codes sont identiques" while the first approval runs does nothing (L1).
    @Test func secondApprovalWhileApprovingIsIgnored() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        try await f.approver.enrollBiometrics(password: testPassword)
        let (n, a, service) = try await f.compare(mode: .personal)
        await n.confirmCode()
        let presence = f.approverHarness.presence
        presence.hold()
        let first = Task { await a.approve(mode: .personal) }
        #expect(await eventually { presence.pending == 1 })
        await a.approve(mode: .personal)
        #expect(presence.biometricPrompts == 1)
        presence.release()
        await first.value
        #expect(await eventually { n.state == .receivedFull })
        #expect(a.state == .done)
        // One grant only: the key exchange, then the grant.
        #expect(f.network.frames(service: service, from: .connector).count == 2)
    }

    /// Approved here, but the new device never confirms: the approver stops after the bound instead
    /// of holding a fresh presence forever (L5).
    @Test func waitForPeerIsBounded() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        f.approverPeerTimeout = .milliseconds(300)
        let (_, a, service) = try await f.compare(mode: .personal)
        await a.approve(mode: .personal, password: testPassword)
        #expect(a.state == .failed(.peerTimedOut))
        #expect(
            PairingFailure.peerTimedOut.message
                == "Le nouvel appareil n'a pas confirmé à temps. Recommence l'appairage.")
        #expect(f.network.frames(service: service, from: .connector).count == 1)
        try await f.approver.refreshDevices()
        #expect(f.approver.devices.count == 1)
    }

    /// Face ID only for approving and revoking, never the device passcode (L4, ruling A8).
    @Test func presenceIsBiometricOnly() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        try await f.approver.enrollBiometrics(password: testPassword)
        let presence = f.approverHarness.presence
        let (n, a, _) = try await f.compare(mode: .personal)
        await n.confirmCode()
        await a.approve(mode: .personal)
        #expect(a.approvalError == nil)
        #expect(presence.biometricPrompts == 1)
        #expect(presence.prompts == 0, "the passcode-capable check is never used")
        #expect(await eventually { n.state == .receivedFull })

        try await f.approver.refreshDevices()
        let other = try #require(f.approver.devices.first { !$0.isThisDevice })
        // Biometrics refused: the master password is asked, not the passcode.
        presence.answer(false)
        await #expect(throws: VaultError.passwordRequired) { try await f.approver.revokeDevice(other.id) }
        presence.answer(true)
        try await f.approver.revokeDevice(other.id)
        #expect(presence.biometricPrompts == 3)
        #expect(presence.prompts == 0)
    }

    /// A guest that floods the journal: the approver keeps the last entries only, labels cut (L3).
    @Test(.timeLimit(.minutes(5))) func publicJournalIsBounded() async throws {
        let f = try await PairingFixture(server: false)
        defer { f.cleanUp() }
        let (n, a, _) = try await f.compare(mode: .public)
        await n.confirmCode()
        let ref = FfiItemRef(vaultId: f.login.vaultId, itemId: f.login.id)
        await a.approvePublic(items: [ref], minutes: 15, password: testPassword)
        var session: PublicSession?
        #expect(await eventually {
            if case .receivedPublic(let s) = n.state { session = s }
            return session != nil
        })
        let guest = try #require(session)
        let total = PairingApproverFlow.maxJournalEntries + 5
        for _ in 0..<(total - 1) { guest.viewed(itemID: f.login.id) }
        guest.copy("valeur-fictive", label: String(repeating: "L", count: 4000), itemID: f.login.id)
        await guest.waitForSends()
        var last: [PairingAuditEntry] = []
        #expect(await eventually {
            if case .publicRunning(let journal, _) = a.state { last = journal }
            return last.last.map { if case .copied = $0.action { true } else { false } } ?? false
        })
        #expect(last.count == PairingApproverFlow.maxJournalEntries)
        #expect(Set(last.map(\.id)).count == last.count, "ids stay unique once the oldest are dropped")
        #expect(last.first?.id == total - PairingApproverFlow.maxJournalEntries)
        if case .copied(let label) = last.last?.action {
            #expect(label.count == PairingApproverFlow.maxAuditLabelLength)
        }
        await a.endPublicSession()
    }
}
