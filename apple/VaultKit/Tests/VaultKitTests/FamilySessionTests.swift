import Foundation
import Testing

@testable import VaultKit

/// Alice creates the family and Bob, her verified contact, joins it as a member.
@MainActor
func familyOfTwo() async throws -> (SharingAccount, SharingAccount) {
    let (alice, bob) = try await verifiedPair()
    let created = try await alice.vault.createFamily(vaultName: "Famille")
    #expect(created.iAmOrganizer)
    try await settleZones([alice])
    let invited = try await alice.vault.inviteToFamily(bob.accountID, role: .member)
    #expect(invited.needsSecondOrganizer)
    try await settleZones([alice, bob])
    try await bob.vault.refreshSharing()
    let invite = try #require(bob.vault.sharing.familyInvites.first)
    #expect(invite.fromNameLocal == "Alice")
    let joined = try await bob.vault.acceptFamilyInvite(invite.id)
    #expect(!joined.iAmOrganizer)
    try await settleZones([alice, bob])
    try await alice.vault.refreshSharing()
    try await bob.vault.refreshSharing()
    await bob.vault.refresh()
    return (alice, bob)
}

/// Sharing plan 4, Task 8: the family and the item sends (spec 11, 14.2).
@MainActor
@Suite(.serialized, .timeLimit(.minutes(20))) struct FamilySessionTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    @Test func receivedItemAcceptIntoVault() async throws {
        let (alice, bob) = try await verifiedPair()
        defer { alice.cleanUp(); bob.cleanUp() }
        let item = try await addItem(alice.vault, title: "Wi-Fi maison", type: .login, vaultID: alice.personalVault)
        try await alice.vault.sendItem(
            item.id, in: alice.personalVault, to: bob.accountID, expiresAt: Date().addingTimeInterval(7 * 24 * 3600))
        try await settleZones([alice, bob])
        try await bob.vault.refreshSharing()
        let received = try #require(bob.vault.sharing.receivedItems.first)
        #expect(received.fromNameLocal == "Alice")
        #expect(received.title == "Wi-Fi maison")
        let kept = try await bob.vault.acceptReceivedItem(received.sendId, into: bob.personalVault)
        #expect(kept.vaultId == bob.personalVault)
        #expect(bob.vault.summaries.contains { $0.title == "Wi-Fi maison" && $0.vaultId == bob.personalVault })
        #expect(bob.vault.sharing.receivedItems.isEmpty)
    }

    @Test func familyMemberSeesOrganizerAndReminder() async throws {
        let (alice, bob) = try await familyOfTwo()
        defer { alice.cleanUp(); bob.cleanUp() }
        let a = try #require(alice.vault.sharing.family)
        let b = try #require(bob.vault.sharing.family)
        #expect(a.familyId == b.familyId)
        // Decision 13: one organizer only, the reminder stays.
        #expect(a.needsSecondOrganizer)
        // The family vault reached Bob.
        #expect(a.vaults.allSatisfy { id in bob.vault.allVaults.contains { $0.id == id } })
    }
}
