import Foundation
import Testing

@testable import VaultKit

/// A scripted org backend: answers from its script and records each call, with the number of
/// biometric prompts `presence` had answered at that moment (so the order of the two shows).
actor FakeOrgBackend: OrgBackend {
    private(set) var calls: [String] = []
    private let presence: FakePresence?
    var local: FfiOrgState?
    var refreshed: Result<FfiOrgState, OnePassError>
    var verified: FfiOrgState?
    var requests: [FfiJoinRequest] = []
    var summaryAllowed = true
    var editError: OnePassError?

    var stateError: OnePassError?

    init(state: FfiOrgState?, presence: FakePresence? = nil, stateError: OnePassError? = nil) {
        local = state
        self.stateError = stateError
        refreshed = state.map { .success($0) } ?? .failure(OnePassError.NotFound)
        self.presence = presence
    }

    func script(refresh: Result<FfiOrgState, OnePassError>) { refreshed = refresh }
    func script(verified: FfiOrgState) { self.verified = verified }
    func script(summaryAllowed: Bool) { self.summaryAllowed = summaryAllowed }
    func script(editError: OnePassError) { self.editError = editError }

    /// The calls by name, in order, without the reads.
    var writes: [String] {
        calls.filter { !["state", "refresh", "joinRequests"].contains(String($0.split(separator: "@")[0])) }
    }

    private func record(_ name: String) { calls.append("\(name)@\(presence?.biometricPrompts ?? 0)") }

    func state() async throws -> FfiOrgState? {
        record("state")
        if let stateError { throw stateError }
        return local
    }

    func pin(source: FfiPinSource, expected: Data?, now: Int64) async throws -> FfiOrgState {
        record("pin")
        let state = try refreshed.get()
        local = state
        return state
    }

    func refresh() async throws -> FfiOrgState {
        record("refresh")
        return try refreshed.get()
    }

    func markVerified() async throws -> FfiOrgState {
        record("markVerified")
        guard let verified else { throw OnePassError.NotFound }
        refreshed = .success(verified)
        return verified
    }

    func joinRequests() async throws -> [FfiJoinRequest] {
        record("joinRequests")
        return requests
    }

    func postJoinRequest(
        session: Session, keys: DeviceKeyPair, invite: FfiOrgInvite, displayName: String, credentialSeed: Data,
        now: Int64
    ) async throws -> FfiJoinPosted {
        record("postJoinRequest")
        return FfiJoinPosted(codeWords: ["a", "b", "c", "d", "e"])
    }

    func revokeOwnCredential() async throws { record("revokeOwnCredential") }

    func declineJoinRequest(accountID: String) async throws { record("decline") }

    func summarize(session: Session, keys: DeviceKeyPair, edit: FfiRosterEdit) async throws -> FfiEditSummary {
        record("summarize")
        return FfiEditSummary(
            memberName: "Bob", deviceCount: 1, rolesBefore: [], rolesAfter: [], stateBefore: .active,
            stateAfter: .suspended, allowed: summaryAllowed)
    }

    func edit(session: Session, keys: DeviceKeyPair, edit: FfiRosterEdit, now: Int64) async throws -> FfiEditOutcome {
        record("edit")
        if let editError { throw editError }
        return FfiEditOutcome(state: try refreshed.get(), serverAccessUpdated: true)
    }

    func createInvite(
        session: Session, keys: DeviceKeyPair, label: String, domain: String?, roles: [FfiOrgRole], now: Int64
    ) async throws -> FfiInviteLink {
        record("createInvite")
        return FfiInviteLink(link: "onepass://org/join", accountId: OrgSessionTests.otherID)
    }

    func ownerKeysAvailable(session: Session, keys: DeviceKeyPair) async throws -> Bool {
        record("ownerKeysAvailable")
        return true
    }

    func setOwners(session: Session, keys: DeviceKeyPair, owners: [String], now: Int64) async throws -> FfiOrgState {
        record("setOwners")
        return try refreshed.get()
    }
}

/// One unlocked personal vault (the session the org calls sign with) and a scripted backend.
@MainActor
struct OrgFixture {
    let harness: SessionHarness
    let vault: VaultSession
    let backend: FakeOrgBackend
    let org: OrgSession

    /// `roles`: this account's roles in the scripted state. `biometrics`: enrolled, so presence is
    /// asked of `FakePresence` (yes by default).
    static func make(
        roles: [FfiOrgRole] = [.admin], source: FfiPinSource = .mdm, biometrics: Bool = true,
        hasState: Bool = true, creating: Bool = false, stateError: OnePassError? = nil
    ) async throws -> OrgFixture {
        let h = try SessionHarness()
        let vault = h.makeSession()
        _ = try await vault.createAccount(password: testPassword, displayName: "Alice", mode: .personal)
        if biometrics { try await vault.enrollBiometrics(password: testPassword) }
        let me = try #require(h.settings.accountID)
        let state = hasState ? try OrgSessionTests.state(me: me, roles: roles, source: source) : nil
        let backend = FakeOrgBackend(state: state, presence: h.presence, stateError: stateError)
        let keys = FixedKeys(
            pair: DeviceKeyPair(
                classical: try generateClassicalDeviceKeys(), pq: try CryptoKitPqHalf.generate(secureEnclave: false)))
        let org = OrgSession(vault: vault, backend: backend, keys: keys, creating: creating)
        await org.load()
        return OrgFixture(harness: h, vault: vault, backend: backend, org: org)
    }

    func cleanUp() { harness.cleanUp() }
}

@MainActor
@Suite("Org session")
struct OrgSessionTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    nonisolated static let otherID = "0123456789abcdef0123456789abcdef"
    nonisolated static let fingerprint = Data((0..<32).map { UInt8($0) })

    static func state(me: String, roles: [FfiOrgRole], source: FfiPinSource) throws -> FfiOrgState {
        FfiOrgState(
            orgId: "5f3e2d1c0b0a99887766554433221100", name: "Acme", fingerprint: fingerprint,
            fingerprintWords: try orgFingerprintWords(fingerprint: fingerprint), dnsValue: "onepass-org=v1",
            source: source, lineageGeneration: 0, rosterSeq: 2,
            owners: roles.contains(.owner) ? [me] : [otherID],
            members: [
                FfiOrgMember(
                    accountId: me, displayName: "Alice", roles: roles, state: .active, devices: [],
                    formerOwner: false),
                FfiOrgMember(
                    accountId: otherID, displayName: "Bob", roles: [], state: .active, devices: [],
                    formerOwner: false),
            ])
    }

    @Test func memberCannotEdit() async throws {
        let f = try await OrgFixture.make(roles: [])
        defer { f.cleanUp() }
        #expect(f.org.phase == .ready)
        #expect(f.org.myRoles.isEmpty)
        #expect(!f.org.canManageMembers)
        await #expect(throws: OrgActionError.notAllowed) {
            _ = try await f.org.apply(.suspend(accountId: Self.otherID), password: nil)
        }
        #expect(await f.backend.writes.isEmpty)
    }

    @Test func editAsksPresenceAfterTheSummary() async throws {
        let f = try await OrgFixture.make(roles: [.admin])
        defer { f.cleanUp() }
        #expect(f.org.canManageMembers)
        _ = try await f.org.apply(.suspend(accountId: Self.otherID), password: nil)
        #expect(await f.backend.writes == ["summarize@0", "edit@1"])
        #expect(f.harness.presence.biometricPrompts == 1)
    }

    @Test func refusedPresenceWritesNothing() async throws {
        let f = try await OrgFixture.make(roles: [.owner])
        defer { f.cleanUp() }
        f.harness.presence.answer(false)
        await #expect(throws: OrgActionError.passwordRequired) {
            _ = try await f.org.apply(.suspend(accountId: Self.otherID), password: nil)
        }
        #expect(await f.backend.writes == ["summarize@0"])
    }

    @Test func withoutBiometricsAPasswordIsRequired() async throws {
        let f = try await OrgFixture.make(roles: [.owner], biometrics: false)
        defer { f.cleanUp() }
        await #expect(throws: OrgActionError.passwordRequired) {
            _ = try await f.org.invite(label: "Bob", domain: nil, password: nil)
        }
        let password = SecretBytes(utf8: testPassword)
        defer { password.wipe() }
        let link = try await f.org.invite(label: "Bob", domain: nil, password: password)
        #expect(link.accountId == Self.otherID)
        #expect(await f.backend.writes == ["createInvite@0"])
    }

    @Test func disallowedSummaryStopsBeforePresence() async throws {
        let f = try await OrgFixture.make(roles: [.userManager])
        defer { f.cleanUp() }
        await f.backend.script(summaryAllowed: false)
        await #expect(throws: OrgActionError.notAllowed) {
            _ = try await f.org.apply(.suspend(accountId: Self.otherID), password: nil)
        }
        #expect(f.harness.presence.biometricPrompts == 0)
        #expect(await f.backend.writes == ["summarize@0"])
    }

    @Test func forkMovesToRefusedAndKeepsState() async throws {
        let f = try await OrgFixture.make()
        defer { f.cleanUp() }
        let before = try #require(f.org.state)
        await f.backend.script(refresh: .failure(OnePassError.Integrity(kind: "org_roster_fork")))
        await f.org.refresh()
        #expect(f.org.phase == .refused(.fork))
        #expect(f.org.state == before)
        #expect(OrgActionError.refused(.fork).message != OrgActionError.refused(.rollback).message)
    }

    @Test func refreshErrorsMapToRefusals() {
        #expect(OrgActionError(OnePassError.Integrity(kind: "org_lineage_rollback")) == .refused(.rollback))
        #expect(OrgActionError(OnePassError.Integrity(kind: "org_lineage_fork")) == .refused(.fork))
        #expect(OrgActionError(OnePassError.Integrity(kind: "org_quorum")) == .refused(.quorum))
        #expect(OrgActionError(OnePassError.Integrity(kind: "org_role_denied")) == .notAllowed)
        #expect(OrgActionError(OnePassError.OrgPinMismatch) == .refused(.pinMismatch))
        #expect(OrgActionError(VaultError.integrity(kind: "org_pin_mismatch")) == .refused(.pinMismatch))
        #expect(OrgActionError(OnePassError.Integrity(kind: "signature")) == .refused(.unreadable))
        #expect(OrgActionError(OnePassError.Validation(field: "owners", reason: "quorum")) == .refused(.quorum))
        #expect(OrgActionError(OnePassError.Validation(field: "roles", reason: "owner via lineage")) == .notAllowed)
        #expect(
            OrgActionError(OnePassError.Validation(field: "roles", reason: "recovery officer via lineage"))
                == .notAllowed)
        #expect(OrgActionError(OnePassError.Locked) == .locked)
        guard case .other(let pending) = OrgActionError(OnePassError.Validation(field: "owners", reason: "pending change")),
              case .other(let keeps) = OrgActionError(
                OnePassError.Validation(field: "owners", reason: "keeps this account"))
        else {
            Issue.record("owner changes in progress are words, not refusals")
            return
        }
        #expect(!pending.isEmpty && !keeps.isEmpty && pending != keeps)
    }

    @Test func aNetworkFailureKeepsThePhase() async throws {
        let f = try await OrgFixture.make()
        defer { f.cleanUp() }
        await f.backend.script(refresh: .failure(OnePassError.MailboxUnavailable(reason: "offline")))
        await f.org.refresh()
        #expect(f.org.phase == .ready)
        #expect(f.org.refreshError != nil)
    }

    @Test func conflictIsReported() async throws {
        let f = try await OrgFixture.make()
        defer { f.cleanUp() }
        await f.backend.script(editError: OnePassError.Conflict)
        await #expect(throws: OrgActionError.conflict) {
            _ = try await f.org.apply(.suspend(accountId: Self.otherID), password: nil)
        }
    }

    @Test func tofuNeedsVerificationUntilMarked() async throws {
        let f = try await OrgFixture.make(source: .tofu(verified: false))
        defer { f.cleanUp() }
        #expect(f.org.needsVerification)
        let me = try #require(f.harness.settings.accountID)
        await f.backend.script(verified: try Self.state(me: me, roles: [.admin], source: .tofu(verified: true)))
        try await f.org.markVerified()
        #expect(!f.org.needsVerification)
        #expect(f.org.state?.source == .tofu(verified: true))
    }

    @Test func unfinishedCreationWithoutState() async throws {
        let f = try await OrgFixture.make(hasState: false, creating: true)
        defer { f.cleanUp() }
        #expect(f.org.phase == .unfinishedCreation)
        #expect(f.org.state == nil)
    }

    @Test func noStateIsNotJoined() async throws {
        let f = try await OrgFixture.make(hasState: false)
        defer { f.cleanUp() }
        #expect(f.org.phase == .notJoined)
    }

    @Test func aLockedVaultSignsNothing() async throws {
        let f = try await OrgFixture.make()
        defer { f.cleanUp() }
        f.vault.lock()
        await #expect(throws: OrgActionError.locked) {
            _ = try await f.org.apply(.suspend(accountId: Self.otherID), password: nil)
        }
        #expect(await f.backend.writes.isEmpty)
    }

    static let invite = FfiOrgInvite(
        serverUrl: "http://127.0.0.1:1/functions/v1/mailbox", mailboxId: "00112233445566778899aabbccddeeff",
        orgId: "5f3e2d1c0b0a99887766554433221100", accountId: otherID, fingerprint: fingerprint,
        nonce: Data(count: 32), credentialSeed: Data(count: 32), memberToken: Data(count: 32), domain: nil)
    static let ownSeed = SecretBytes(copying: Data(repeating: 6, count: 32))

    /// R31: the join request is signed by this device, so presence comes first.
    @Test func joinRequestAsksPresenceFirst() async throws {
        let f = try await OrgFixture.make(roles: [])
        defer { f.cleanUp() }
        _ = try await f.org.requestToJoin(
            invite: Self.invite, displayName: "Alice", password: nil, ownCredential: Self.ownSeed)
        #expect(await f.backend.writes == ["postJoinRequest@1"])
    }

    @Test func refusedPresencePostsNoJoinRequest() async throws {
        let f = try await OrgFixture.make(roles: [])
        defer { f.cleanUp() }
        f.harness.presence.answer(false)
        await #expect(throws: OrgActionError.passwordRequired) {
            _ = try await f.org.requestToJoin(
            invite: Self.invite, displayName: "Alice", password: nil, ownCredential: Self.ownSeed)
        }
        #expect(await f.backend.writes.isEmpty)
    }

    @Test func anUnreadablePinLeavesLoading() async throws {
        let f = try await OrgFixture.make(stateError: .Store)
        defer { f.cleanUp() }
        #expect(f.org.phase == .unavailable)
        #expect(f.org.refreshError != nil)
        #expect(f.org.state == nil)
    }

    @Test func onlyAnOwnerSetsOwners() async throws {
        let f = try await OrgFixture.make(roles: [.admin])
        defer { f.cleanUp() }
        await #expect(throws: OrgActionError.notAllowed) {
            try await f.org.setOwners([Self.otherID], password: nil)
        }
        #expect(await f.backend.writes.isEmpty)
    }
}

/// Swaps the global strings bundle, so apart from the other suites' tests.
@MainActor
@Suite("Org fingerprint words", .serialized)
struct OrgWordsTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    /// The words come from the core, which knows no language: the same under every catalog.
    @Test func wordsAreTheSameWhateverTheLanguage() throws {
        let fingerprint = OrgSessionTests.fingerprint
        let reference = try orgFingerprintWords(fingerprint: fingerprint)
        var shown: [String: [[String]]] = [:]
        // No suspension point between the swap and the restore: no other main actor test sees it.
        let pinned = VaultKitStrings.bundle
        defer { VaultKitStrings.bundle = pinned }
        for language in ["en", "fr", "es", "it"] {
            let path = try #require(Bundle.module.path(forResource: language, ofType: "lproj"))
            VaultKitStrings.bundle = try #require(Bundle(path: path))
            #expect(VaultKitStrings.language == language)
            shown[language] = try orgFingerprintWords(fingerprint: fingerprint)
        }
        #expect(shown.count == 4 && shown.values.allSatisfy { $0 == reference })
        #expect(reference.count == 4 && reference.allSatisfy { $0.count == 5 })
    }
}
