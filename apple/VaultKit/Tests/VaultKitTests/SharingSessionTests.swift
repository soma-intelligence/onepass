import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// Zone seeds in memory (the Keychain's job in the app).
final class MemZoneSeeds: FfiZoneSeedStore, @unchecked Sendable {
    private let seeds = Mutex<[Data: Data]>([:])
    func get(mailboxId: Data) -> Data? { seeds.withLock { $0[mailboxId] } }
    func put(mailboxId: Data, seed: Data) { seeds.withLock { $0[mailboxId] = seed } }
    func delete(mailboxId: Data) { _ = seeds.withLock { $0.removeValue(forKey: mailboxId) } }
}

/// Records the local notifications.
final class RecordingNotifier: LocalNotifying, @unchecked Sendable {
    private let posts = Mutex<[(title: String, body: String)]>([])
    func post(id: String, title: String, body: String) { posts.withLock { $0.append((title, body)) } }
    var bodies: [String] { posts.withLock { $0.map(\.body) } }
}

/// One account with v2 device keys behind a real `VaultSession`, its zones synced against the test
/// mailbox server of the framework (`test_mailbox_start`, loopback TLS). Synthetic data only.
@MainActor
final class SharingAccount {
    let name: String
    let harness: SessionHarness
    let vault: VaultSession
    let notifier = RecordingNotifier()
    let classical: Data
    let pq: any FfiPqDeviceHalf
    let secretKey: String
    let seeds = MemZoneSeeds()
    let zones: ZoneSyncHandle
    let store: SyncStoreHandle
    let accountID: String

    init(_ name: String, server: FfiMailboxEndpoint) async throws {
        self.name = name
        harness = try SessionHarness()
        let path = harness.environment.databaseURL.path
        let (classical, pq) = (try generateClassicalDeviceKeys(), try testSoftwarePqHalf())
        self.classical = classical
        self.pq = pq
        let created = try await CoreThread.run {
            try createAccountV2(
                dbPath: path, password: testPassword, kdf: sharingFastKdf, classical: classical, pq: pq,
                name: "iPhone de \(name)", kind: .phone, mode: .personal)
        }
        accountID = created.session.accountId()
        created.session.lock()
        secretKey = created.secretKey
        var environment = harness.environment
        environment.notifier = notifier
        vault = VaultSession(environment: environment)
        try await vault.restore(secretKey: created.secretKey, password: testPassword)
        zones = ZoneSyncHandle(seeds: seeds, defaultBaseUrl: server.baseUrl, extraCaPem: server.extraCaPem)
        store = try openSyncStore(dbPath: path)
    }

    var path: String { harness.environment.databaseURL.path }
    var core: Session { vault.coreSession! }
    var keys: any DeviceKeySource { FixedKeys(pair: DeviceKeyPair(classical: classical, pq: pq)) }
    var personalVault: String { vault.allVaults[0].id }

    /// One zone round, unlocked or (`locked`) from the cached seeds only.
    @discardableResult
    func round(locked: Bool = false) async throws -> FfiZoneRoundReport {
        let (zones, store, session) = (zones, store, locked ? nil : vault.coreSession)
        let now = Int64(Date().timeIntervalSince1970)
        return try await CoreThread.run { zones.runRound(session: session, store: store, now: now) }
    }

    func cleanUp() {
        vault.lock()
        harness.cleanUp()
    }
}

/// Rounds for everyone until two quiet passes in a row (the Rust tests' `settle_zones`).
@MainActor
func settleZones(_ people: [SharingAccount]) async throws {
    var quiet = 0
    for _ in 0..<12 {
        var allQuiet = true
        for p in people {
            let r = try await p.round()
            if r.actionsDone != 0 || r.rerun || r.changed || r.zones.contains(where: { $0.status != .idle }) {
                allQuiet = false
            }
        }
        quiet = allQuiet ? quiet + 1 : 0
        if quiet == 2 { return }
    }
    Issue.record("zones never settled")
}

/// Alice and Bob, verified in person over the in-memory contact service; the pair's mailbox lives
/// on the test server.
@MainActor
func verifiedPair() async throws -> (SharingAccount, SharingAccount) {
    let server = try testMailboxStart()
    let alice = try await SharingAccount("Alice", server: server)
    let bob = try await SharingAccount("Bob", server: server)
    let service = InMemoryPairingNetwork().service(LocalNetworkPairingTransport.contactServiceType)
    func flow(_ p: SharingAccount) -> ContactVerificationFlow {
        ContactVerificationFlow(
            session: p.core, myName: p.name, keys: p.keys, listener: service, connector: service,
            creator: ContactZoneCreator(handle: p.zones))
    }
    let (shower, scanner) = (flow(alice), flow(bob))
    shower.showCode()
    try await waitFor { if case .showingQR = shower.state { true } else { false } }
    guard case .showingQR(let qr) = shower.state else { throw PairingFailure.refused }
    scanner.scan(qrText: qr)
    try await waitFor { if case .comparing = shower.state, case .comparing = scanner.state { true } else { false } }
    shower.confirm()
    scanner.confirm()
    try await waitFor {
        switch (shower.state, scanner.state) {
        case (.done, .done), (.failed, _), (_, .failed): true
        default: false
        }
    }
    guard case .done = shower.state, case .done = scanner.state else {
        Issue.record("verification: \(shower.state) / \(scanner.state)")
        throw PairingFailure.refused
    }
    try await settleZones([alice, bob])
    try await alice.vault.refreshSharing()
    try await bob.vault.refreshSharing()
    return (alice, bob)
}

/// Sharing plan 4, Task 8: the sharing session model on a real core, two accounts and the test
/// mailbox server.
@MainActor
@Suite(.serialized, .timeLimit(.minutes(20))) struct SharingSessionTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    /// Alice shares her personal vault with Bob (Read) and Bob joins it.
    private func sharedWithBob(role: FfiRole = .read, titles: [String] = []) async throws -> (SharingAccount, SharingAccount, String) {
        let (alice, bob) = try await verifiedPair()
        // The last vault cannot leave the private zone: share a second one.
        try await alice.vault.createVault(FfiVaultMeta(
            name: "Projet Atlas", icon: "folder", color: "purple", travelSafe: false, mcpAccess: false))
        let vaultID = try #require(alice.vault.allVaults.first { $0.meta.name == "Projet Atlas" }?.id)
        for title in titles { try await addItem(alice.vault, title: title, type: .login, vaultID: vaultID) }
        let shared = try await alice.vault.shareVault(vaultID)
        #expect(shared.owner)
        #expect(alice.vault.sharing.sharedVaults.map(\.vaultId) == [vaultID])
        // A member is added once the zone round made the vault's mailbox.
        await #expect(throws: VaultError.validation(field: "zone", reason: "not created yet")) {
            try await alice.vault.addMember(bob.accountID, to: vaultID, role: role)
        }
        try await settleZones([alice])
        try await alice.vault.addMember(bob.accountID, to: vaultID, role: role)
        #expect(alice.vault.sharing.sharedVaults.first?.members.count == 2)
        try await settleZones([alice, bob])
        try await bob.vault.refreshSharing()
        let invite = try #require(bob.vault.sharing.shareInvites.first)
        #expect(invite.fromNameLocal == "Alice")
        #expect(invite.role == role)
        try await bob.vault.acceptShareInvite(invite.id)
        try await settleZones([alice, bob])
        try await bob.vault.refreshSharing()
        await bob.vault.refresh()
        #expect(bob.vault.sharing.sharedVaults.map(\.vaultId) == [vaultID])
        #expect(bob.vault.sharing.shareInvites.isEmpty)
        return (alice, bob, vaultID)
    }

    @Test func shareAddRemoveUpdatesPublishedState() async throws {
        let (alice, bob, vaultID) = try await sharedWithBob(role: .write)
        defer { alice.cleanUp(); bob.cleanUp() }
        #expect(bob.vault.sharing.sharedVaults.first?.role == .write)
        // Bob sees the vault and Alice's member list names him from her book.
        #expect(bob.vault.allVaults.contains { $0.id == vaultID })
        let members = try #require(alice.vault.sharing.sharedVaults.first?.members)
        #expect(Set(members.map(\.accountId)) == [alice.accountID, bob.accountID])
        #expect(members.first { $0.accountId == bob.accountID }?.nameLocal == "Bob")

        _ = try await alice.vault.removeMember(bob.accountID, from: vaultID)
        #expect(alice.vault.sharing.sharedVaults.first?.members.map(\.accountId) == [alice.accountID])
        try await settleZones([alice, bob])
        try await bob.vault.refreshSharing()
        #expect(bob.vault.sharing.sharedVaults.isEmpty)
        // A lock empties the published state.
        alice.vault.lock()
        #expect(alice.vault.sharing == SharingSnapshot())
    }

    @Test func removalPromptCountsSeenItems() async throws {
        let (alice, bob, vaultID) = try await sharedWithBob(titles: ["Banque", "Messagerie"])
        defer { alice.cleanUp(); bob.cleanUp() }
        let prompt = try await alice.vault.removeMember(bob.accountID, from: vaultID)
        #expect(prompt.seenItems == 2)
        #expect(prompt.message == "Bob ne verra plus rien de nouveau dans Projet Atlas. Il a pu garder ce qu'il a déjà vu : 2 mots de passe. Les changer ?")
        // Watchtower "Vus par un ancien membre".
        let seen = try await alice.vault.seenByFormerMemberItems()
        #expect(Set(seen.map(\.title)) == ["Banque", "Messagerie"])
        #expect(VaultSession.seenByFormerMemberTitle == "Vus par un ancien membre")
    }

    @Test func rekeyNoticePostedAfterSync() async throws {
        let (alice, bob, vaultID) = try await sharedWithBob()
        defer { alice.cleanUp(); bob.cleanUp() }
        let before = try #require(alice.vault.sharing.sharedVaults.first?.generation)
        try await bob.vault.leaveSharedVault(vaultID)
        try await settleZones([alice, bob])
        let notices = try await alice.vault.afterSyncRound()
        #expect(notices.map(\.reason) == [.leave])
        #expect(alice.notifier.bodies == ["Clé du coffre Projet Atlas renouvelée"])
        #expect((alice.vault.sharing.sharedVaults.first?.generation ?? 0) > before)
        // Nothing left to answer: no second notification.
        try await alice.vault.afterSyncRound()
        #expect(alice.notifier.bodies.count == 1)
    }

    /// Decision 6 and ruling C-2: the code for a reader, in person for a writer or a manager. The
    /// offer only reads the core's roles; the change itself is synthetic.
    @Test func identityChangeReaderOffersCodeWriterOffersInPerson() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        func member(_ role: FfiRole) -> FfiMember {
            FfiMember(accountId: "b0b", nameLocal: "Bob", role: role, owner: false, level: .verified, keysChanged: true, keyPending: false)
        }
        func vault(_ id: String, _ role: FfiRole) -> FfiSharedVault {
            FfiSharedVault(
                vaultId: id, name: id, role: .manage, owner: true, generation: 2, members: [member(role)],
                identityPending: false, mcpHidden: false)
        }
        let issued = Date(timeIntervalSince1970: 1_793_000_000)
        let change = FfiIdentityChange(
            accountId: "b0b", nameLocal: "Bob", child: String(repeating: "ab", count: 32), rotatorName: "iPhone de Bob",
            revokedNames: ["Mac de Bob"], issuedAt: Int64(issued.timeIntervalSince1970), vaults: ["v1", "v2"], forked: false)
        let date = VaultSession.longDate(issued)

        session.sharing.sharedVaults = [vault("v1", .read), vault("v2", .read)]
        #expect(session.identityChangeOffer(for: change) == .code(message:
            "Les clés de Bob ont changé le \(date) (iPhone de Bob a retiré Mac de Bob). Demande-lui le code affiché sur son iPhone."))

        session.sharing.sharedVaults = [vault("v1", .read), vault("v2", .write)]
        #expect(session.identityChangeOffer(for: change) == .inPerson(message:
            "Les clés de Bob ont changé le \(date). Pour lui rendre l'accès, vérifiez-vous en personne avec le QR."))

        session.sharing.sharedVaults = [vault("v1", .manage)]
        if case .inPerson = session.identityChangeOffer(for: change) {} else { Issue.record("a manager is checked in person") }

        var forked = change
        forked.forked = true
        #expect(session.identityChangeOffer(for: forked) == .forked(message:
            "Deux appareils de Bob se sont retirés l'un l'autre. Lequel a-t-elle encore en main ?"))
    }
}
