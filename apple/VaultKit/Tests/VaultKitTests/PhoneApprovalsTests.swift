import Foundation
import Testing

@testable import VaultKit

/// The "iPhone" card of Réglages > Développeur on the Mac (agent-ready spec 7): the enrolled phones,
/// "Approuver aussi sur l'iPhone", "Déverrouiller depuis mon iPhone" (Touch ID first) and the window.
/// The Mac page itself cannot run under XCUITest unattended (Automation Mode needs the owner's
/// password), so its model is tested here with Touch ID simulated by the fake keyring.
@MainActor
@Suite("Mac iPhone card", .timeLimit(.minutes(5)))
struct PhoneApprovalsTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    private func card(_ f: RemoteUnlockFixture) -> PhoneApprovals {
        PhoneApprovals(
            vault: f.vault, hosts: f.hosts, coordinator: f.coordinator,
            approverKeys: ApproverKeyStore(keychain: f.macKeychain))
    }

    @Test func cardListsThePhoneAndRacesItOnTheSharedMailbox() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let card = card(f)
        await card.start()
        await card.sessionUnlocked()

        #expect(card.available)
        #expect(card.phones.map(\.name) == ["iPhone de Camille"])
        #expect(card.approveOnPhone)
        #expect(f.hosts.originLabel("phone:\(f.phone.id)") == "iPhone de Camille")
        // The full-unlock approver reads through the coordinator's mailbox, never a second one.
        let approver = try #require(f.hosts.remoteApprover)
        #expect(approver.mailbox === f.coordinator.mailbox(for: f.macId))

        await card.setApproveOnPhone(false)
        #expect(!f.hosts.remoteApproverSet)
        #expect(DeveloperSettings.load(from: UserDefaults(suiteName: f.suite)!).approveOnPhone == false)
        await card.setApproveOnPhone(true)
        #expect(f.hosts.remoteApproverSet)
    }

    @Test func unlockSwitchAsksTouchIDFirst() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let card = card(f)
        await card.start()
        await card.sessionUnlocked()
        #expect(card.unlockPhone == nil)

        // Touch ID cancelled: nothing is enrolled, nothing is sent.
        f.harness.keyring.failNextDecrypt(with: .cancelled)
        await card.setUnlockFromPhone(true)
        #expect(card.unlockPhone == nil)
        #expect(card.errorMessage != nil)
        #expect(try f.store.load() == nil)
        #expect(f.channel.stored().isEmpty)

        // Touch ID accepted: `C` kept here, `K_r` on its way to the phone, the code shown.
        await card.setUnlockFromPhone(true)
        #expect(card.unlockPhone == f.phone.id)
        #expect(card.errorMessage == nil)
        #expect(card.pairingCode?.isEmpty == false)
        #expect(try f.store.load() != nil)
        #expect(f.channel.stored().contains { $0.to == f.phone.id })

        // Off: `C` erased on this Mac.
        await card.setUnlockFromPhone(false)
        #expect(card.unlockPhone == nil)
        #expect(card.pairingCode == nil)
        #expect(try f.store.load() == nil)
    }

    @Test func windowDurationDefaultsToAnHourWithinRange() async throws {
        let f = try await RemoteUnlockFixture.make()
        defer { f.cleanUp() }
        let card = card(f)
        #expect(card.windowMinutes == 60)
        #expect(PhoneApprovals.windowChoices.first == 15)
        #expect(PhoneApprovals.windowChoices.last == 480)
        #expect(PhoneApprovals.windowChoices.contains(60))
        await card.setWindowMinutes(5)
        #expect(card.windowMinutes == 15)
        await card.setWindowMinutes(600)
        #expect(card.windowMinutes == 480)
        await card.setWindowMinutes(120)
        #expect(card.windowMinutes == 120)
    }

    /// Without CloudKit (unsigned builds, UI tests) the card says so and nothing is wired.
    @Test func withoutAChannelTheCardIsUnavailable() async throws {
        let harness = try SessionHarness()
        defer { harness.cleanUp() }
        let vault = harness.makeSession()
        _ = try await vault.createAccount(password: testPassword, displayName: "", mode: .personal)
        let hosts = DeveloperHosts(
            paths: DeveloperPaths(dataDirectory: URL(fileURLWithPath: "/tmp/op-none"), relay: URL(fileURLWithPath: "/x")),
            defaults: UserDefaults(suiteName: "onepass.tests.card.\(UUID().uuidString)")!, presence: FakePresence())
        let card = PhoneApprovals(vault: vault, hosts: hosts, coordinator: nil, approverKeys: ApproverKeyStore(keychain: InMemoryKeychain()))
        await card.start()
        await card.sessionUnlocked()
        #expect(!card.available)
        #expect(card.phones.isEmpty)
        #expect(!hosts.remoteApproverSet)
        await card.setUnlockFromPhone(true)
        #expect(card.unlockPhone == nil)
        vault.lock()
    }
}
