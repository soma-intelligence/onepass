import Foundation
import Testing

@testable import VaultKit

/// Two managed accounts in two folders against the in-process org server (real FFI, software keys).
@MainActor
@Suite("Org integration")
struct OrgIntegrationTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    private static func now() -> Int64 { Int64(Date().timeIntervalSince1970) }

    /// A managed account for `orgID` made by `vault` (of `h`), its keys adopted under the new account id.
    private static func managedAccount(
        _ h: SessionHarness, _ vault: VaultSession, name: String, orgID: String, accountID: String?
    ) async throws -> ManagedDeviceKeys {
        let slot = UUID().uuidString
        let pending = try ManagedDeviceKeys.createPending(keychain: h.keychain, slot: slot, secureEnclave: false)
        let password = SecretBytes(utf8: testPassword)
        defer { password.wipe() }
        let secretKey = try await vault.createManagedAccount(
            password: password, displayName: name, mode: .personal, orgID: orgID, accountID: accountID,
            keys: pending)
        secretKey.wipe()
        let account = try #require(h.settings.accountID)
        try ManagedDeviceKeys.adoptPending(keychain: h.keychain, slot: slot, accountID: account)
        return ManagedDeviceKeys(keychain: h.keychain, accountID: account)
    }

    @Test func ownerAcceptsAJoinerEndToEnd() async throws {
        let server = TestOrgServer()
        let ownerHarness = try SessionHarness()
        defer { ownerHarness.cleanUp() }
        let joinerHarness = try SessionHarness()
        defer { joinerHarness.cleanUp() }
        let ownerDir = ownerHarness.dir.appendingPathComponent("org").path
        let joinerDir = joinerHarness.dir.appendingPathComponent("org").path

        // The owner makes the org: its account first, then the publish.
        let draft = try OrgDraft()
        let orgID = draft.orgId()
        let ownerVault = ownerHarness.makeSession()
        let ownerKeys = try await Self.managedAccount(
            ownerHarness, ownerVault, name: "Alice", orgID: orgID, accountID: nil)
        try await ownerVault.enrollBiometrics(password: testPassword)
        let pair = try ownerKeys.deviceKeys()
        let created = try server.draftPublish(
            draft: draft, session: try #require(ownerVault.coreSession), classical: pair.classical, pq: pair.pq,
            name: "Acme", stateDir: ownerDir, now: Self.now())
        let ownerClient = try server.client(
            mailboxId: created.mailboxId, credentialSeed: created.credentialSeed, orgId: orgID, stateDir: ownerDir)
        let owner = OrgSession(vault: ownerVault, backend: FfiOrgBackend(client: ownerClient), keys: ownerKeys)
        await owner.load()
        #expect(owner.phase == .ready)
        #expect(owner.state?.rosterSeq == 1)
        let ownerState = try #require(owner.state)
        #expect(ownerState.fingerprintWords == (try orgFingerprintWords(fingerprint: ownerState.fingerprint)))
        #expect(owner.myRoles == [.owner])
        #expect(owner.isOwner && owner.canManageMembers)
        #expect(await owner.ownerKeysAvailable())

        // The invitation travels as a link.
        let link = try await owner.invite(label: "Bob", domain: nil, password: nil)
        let invite = try orgInviteParse(link: link.link, allowLoopbackHttp: true)
        #expect(invite.accountId == link.accountId)

        // The joiner pins with the link's fingerprint before its account exists, then joins.
        let linkClient = try server.client(
            mailboxId: invite.mailboxId, credentialSeed: invite.credentialSeed, orgId: invite.orgId,
            stateDir: joinerDir)
        let joinerVault = joinerHarness.makeSession()
        let joinerKeys = ManagedDeviceKeys(keychain: joinerHarness.keychain, accountID: invite.accountId)
        let joiner = OrgSession(vault: joinerVault, backend: FfiOrgBackend(client: linkClient), keys: joinerKeys)
        try await joiner.pin(.pin(source: .tofu(verified: false), expected: invite.fingerprint))
        #expect(joiner.needsVerification)
        #expect(joiner.state?.fingerprint == owner.state?.fingerprint)
        _ = try await Self.managedAccount(
            joinerHarness, joinerVault, name: "Bob", orgID: invite.orgId, accountID: invite.accountId)
        // No biometrics on the joiner: the master password is the presence check (R31).
        await #expect(throws: OrgActionError.passwordRequired) {
            _ = try await joiner.requestToJoin(invite: invite, displayName: "Bob", password: nil)
        }
        let password = SecretBytes(utf8: testPassword)
        defer { password.wipe() }
        let posted = try await joiner.requestToJoin(invite: invite, displayName: "Bob", password: password)
        #expect(posted.codeWords.count == 5)
        #expect(joiner.me?.state == .invited)

        // The owner sees the request with the same words and accepts it.
        await owner.refresh()
        #expect(owner.joinRequests.count == 1)
        let request = try #require(owner.joinRequests.first)
        #expect(request.codeWords == posted.codeWords)
        #expect(request.displayName == "Bob")
        let summary = try await owner.summary(for: .accept(accountId: request.accountId, roles: []))
        #expect(summary.allowed && summary.memberName == "Bob")
        let outcome = try await owner.apply(.accept(accountId: request.accountId, roles: []), password: nil)
        #expect(outcome.serverAccessUpdated)
        #expect(owner.joinRequests.isEmpty)

        // The inviting device revoked the link's credential on accept (R29): the joiner's link
        // client fails from now on, and keeps its last good state.
        await joiner.refresh()
        #expect(joiner.refreshError != nil)
        #expect(joiner.phase == .ready)
        #expect(joiner.me?.state == .invited)

        // R27: the member reopens with its own credential and sees itself Active.
        let ownClient = try server.client(
            mailboxId: invite.mailboxId, credentialSeed: posted.credentialSeed, orgId: invite.orgId,
            stateDir: joinerDir)
        let member = OrgSession(vault: joinerVault, backend: FfiOrgBackend(client: ownClient), keys: joinerKeys)
        await member.load()
        #expect(member.phase == .ready)
        #expect(member.refreshError == nil)
        #expect(member.me?.state == .active)
        #expect(!member.canManageMembers)
        await member.refresh()
        #expect(member.refreshError == nil)
    }
}
