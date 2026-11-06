import Foundation
import Testing

@testable import VaultKit

/// Sharing plan 4, Task 8: organizer-assisted recovery (spec 11.4 to 11.7) between two real
/// sessions, zones on the test mailbox server, the handshake over the in-memory contact service.
@MainActor
@Suite(.serialized, .timeLimit(.minutes(20))) struct RecoveryFlowTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    private static let day: TimeInterval = 24 * 3600

    /// Bob enrolls with Alice (a day), Alice asks at `t`.
    private func requested() async throws -> (SharingAccount, SharingAccount, FfiRecoveryEnrollment, Date) {
        let (alice, bob) = try await familyOfTwo()
        #expect(VaultSession.recoveryRiskText(organizer: "Alice", mailboxAccount: false)
            == "Alice et quelqu'un qui aurait accès à ton compte iCloud pourraient ensemble ouvrir ton coffre.")
        #expect(VaultSession.recoveryRiskText(organizer: "Alice", mailboxAccount: true)
            == "Alice et quelqu'un qui aurait ton Emergency Kit pourraient ensemble ouvrir ton coffre.")
        let t = Date()
        let enrollment = try await bob.vault.enrollRecovery(
            organizer: alice.accountID, delaySecs: UInt32(Self.day), password: SecretBytes(utf8: testPassword), at: t)
        #expect(enrollment.organizerNameLocal == "Alice")
        #expect(bob.vault.sharing.recoveryEnrollment == enrollment)
        try await settleZones([alice, bob])
        try await alice.vault.refreshSharing()
        let helper = try #require(alice.vault.sharing.helpers.first)
        #expect(VaultSession.helperMessage(helper) == "Bob t'a choisi pour l'aider à récupérer son compte.")
        let status = try await alice.vault.requestRecovery(of: bob.accountID, password: SecretBytes(utf8: testPassword), at: t)
        #expect(status == .waiting(releaseAfter: Int64(t.timeIntervalSince1970) + Int64(Self.day)))
        try await settleZones([alice, bob])
        return (alice, bob, enrollment, t)
    }

    @Test func recoveryAlertShownWhileLocked() async throws {
        let (alice, bob, enrollment, t) = try await requested()
        defer { alice.cleanUp(); bob.cleanUp() }
        bob.vault.lock()
        #expect(bob.vault.state == .locked)
        await bob.vault.refreshRecoveryAlerts()
        let alert = try #require(bob.vault.recoveryAlerts.first)
        #expect(alert.enrollmentId == enrollment.enrollmentId)
        let release = Date(timeIntervalSince1970: TimeInterval(alert.releaseAfter))
        #expect(alert.releaseAfter == Int64(t.timeIntervalSince1970) + Int64(Self.day))
        #expect(VaultSession.recoveryAlertMessage(alert)
            == "Alice a demandé à récupérer ton compte. Ce sera possible le \(VaultSession.longDate(release)) à \(VaultSession.shortTime(release)). Si ce n'est pas toi, annule.")
    }

    @Test func cancelFromLockedDevice() async throws {
        let (alice, bob, enrollment, t) = try await requested()
        defer { alice.cleanUp(); bob.cleanUp() }
        bob.vault.lock()
        let at = t.addingTimeInterval(60)
        try await bob.vault.cancelRecovery(enrollment.enrollmentId, keys: bob.keys, at: at)
        // The cancel travels in the zone round of the locked device (cached seeds).
        for _ in 0..<4 {
            try await bob.round(locked: true)
            try await alice.round()
        }
        let status = try await alice.vault.recoveryStatus(of: bob.accountID, at: t.addingTimeInterval(2 * Self.day))
        #expect(status == .cancelled(at: Int64(at.timeIntervalSince1970)))
    }

    @Test func releaseThenRecoverEndToEnd() async throws {
        let (alice, bob, _, t) = try await requested()
        defer { alice.cleanUp(); bob.cleanUp() }
        let releaseAfter = t.addingTimeInterval(Self.day)
        #expect(try await alice.vault.recoveryStatus(of: bob.accountID, at: releaseAfter.addingTimeInterval(-1))
            == .waiting(releaseAfter: Int64(releaseAfter.timeIntervalSince1970)))
        #expect(try await alice.vault.recoveryStatus(of: bob.accountID, at: releaseAfter) == .ready)
        try await addItem(bob.vault, title: "Banque", type: .login, vaultID: bob.personalVault)

        // Bob's new device: his private base fetched into an empty store, nothing unlocked.
        let at = releaseAfter.addingTimeInterval(5)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-recover-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let newPath = dir.appendingPathComponent("v.db").path
        let rows = try bob.store.pendingChanges()
        let fresh = try openSyncStore(dbPath: newPath)
        for c in rows {
            try fresh.stageRemote(record: FfiRemoteRecord(
                kind: c.kind, id: c.id, version: c.version, data: c.data, serverMeta: Data("tag".utf8)))
        }
        _ = try fresh.commitRemoteChecked(now: UInt64(at.timeIntervalSince1970))

        let service = InMemoryPairingNetwork().service(LocalNetworkPairingTransport.contactServiceType)
        let keychain = InMemoryKeychain()
        let newKeys = FixedKeys(pair: DeviceKeyPair(classical: try generateClassicalDeviceKeys(), pq: try testSoftwarePqHalf()))
        let member = RecoverWithHelpFlow(dbPath: newPath, keychain: keychain, listener: service, now: { at })
        let organizer = RecoveryReleaseFlow(session: alice.core, member: bob.accountID, connector: service, now: { at })
        member.start()
        try await waitFor { if case .showingQR = member.state { true } else { false } }
        guard case .showingQR(let qr) = member.state else { return }
        organizer.scan(qrText: qr)
        try await waitFor { if case .comparing = member.state, case .comparing = organizer.state { true } else { false } }
        guard case .comparing(let sas) = member.state else { return }
        #expect(organizer.state == .comparing(sas: sas))
        member.confirm(
            newPassword: "un tout nouveau mot de passe", kitSecretKey: nil, keys: newKeys,
            deviceName: "iPhone de secours", kind: .phone, mode: .personal)
        organizer.confirm()
        try await waitFor {
            switch (member.state, organizer.state) {
            case (.done, .done), (.failed, _), (_, .failed): true
            default: false
            }
        }
        guard case .done(let newSecretKey) = member.state else {
            Issue.record("recovery: \(member.state) / \(organizer.state)")
            return
        }
        #expect(organizer.state == .done)
        #expect(try keychain.read(RecoverWithHelpFlow.pendingSecretKeyKey) == Data(newSecretKey.utf8))
        let recovered = try #require(member.session)
        #expect(try recovered.itemSummaries().contains { $0.title == "Banque" })
    }
}
