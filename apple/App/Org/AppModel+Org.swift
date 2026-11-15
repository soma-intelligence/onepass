import Foundation
import VaultKit
import os

/// A managed account being made in the onboarding: its slot, and whether it creates its organisation
/// (with the server's invite for the org mailbox) or joins one from a link.
struct ManagedOnboarding: Equatable {
    enum Route: Equatable {
        case create(name: String, serverInvite: String)
        case join(FfiOrgInvite)
    }

    let slot: String
    let route: Route
}

extension AppModel {
    private static var orgLog: Logger { Logger(subsystem: "me.somalabs.onepass", category: "org") }

    // MARK: - Starting

    /// Starts a new organisation: its draft (the org id), a managed slot on `serverURL`, then the sign
    /// up of the onboarding on that slot. Nothing reaches the server before the account exists.
    func beginOrgCreation(name: String, serverURL: URL, serverInvite: String) throws(AccountsError) {
        let draft: OrgDraft
        do {
            draft = try OrgDraft()
        } catch {
            throw .directory(VaultError(error))
        }
        let kind = FfiAccountKind.managed(serverUrl: serverURL.absoluteString, orgId: draft.orgId())
        try beginAddingAccount(kind: kind, label: name, color: .indigo, signIn: false)
        let slot = accounts.activeSlot
        accounts.session(for: slot)?.environment.settings.orgCreator = true
        orgDraft = draft
        managedOnboarding = ManagedOnboarding(slot: slot, route: .create(name: name, serverInvite: serverInvite))
    }

    /// Starts joining the organisation of `invite`: the pin plan (MDM, DNS, else first use), a managed
    /// slot, the link's secrets in the keychain, then the pin, before the account exists. Any failure
    /// takes the slot out again.
    func beginOrgJoin(_ invite: FfiOrgInvite) async throws(OrgActionError) -> FfiOrgState {
        let plan = await OrgPinResolver(mdm: ManagedOrgConfig.read(), dns: SystemDNSTXTResolver()).plan(for: invite)
        // Refused before any slot exists.
        if let refusal = plan.refusal { throw refusal }
        let kind = FfiAccountKind.managed(serverUrl: invite.serverUrl, orgId: invite.orgId)
        do {
            try beginAddingAccount(kind: kind, label: invite.domain ?? "", color: .indigo, signIn: false)
        } catch {
            throw .other(error.message)
        }
        let slot = accounts.activeSlot
        managedOnboarding = ManagedOnboarding(slot: slot, route: .join(invite))
        do throws(OrgActionError) {
            return try await pinJoinedOrg(invite, plan: plan, slot: slot)
        } catch {
            cancelOrgJoin()
            throw error
        }
    }

    /// The join's settings and keychain items on `slot`, then the pin.
    private func pinJoinedOrg(_ invite: FfiOrgInvite, plan: OrgPinPlan, slot: String) async throws(OrgActionError)
        -> FfiOrgState
    {
        let missing = OrgActionError.other(VaultError.notFound.localizedMessage)
        guard let vault = accounts.session(for: slot) else { throw missing }
        let settings = vault.environment.settings
        settings.orgMailboxID = invite.mailboxId
        settings.orgJoinNonce = invite.nonce.map { String(format: "%02x", $0) }.joined()
        let credentials = ManagedOrgCredentials(keychain: vault.environment.keychain, slot: slot)
        do {
            try credentials.storeLinkSeed(SecretBytes(copying: invite.credentialSeed))
            try credentials.storeMemberToken(SecretBytes(copying: invite.memberToken))
        } catch {
            throw .other(VaultError(error).localizedMessage)
        }
        guard let org = orgSession(for: slot) else { throw missing }
        try await org.pin(plan)
        guard let state = org.state else { throw missing }
        return state
    }

    /// Leaves a managed sign up before its account exists (creation or join): the slot, its pending
    /// device keys and its org credentials go (`AccountSessions.discard`).
    func cancelOrgJoin() {
        guard let onboarding = managedOnboarding else { return }
        managedOnboarding = nil
        orgDraft = nil
        orgSessions[onboarding.slot] = nil
        orgBackends[onboarding.slot] = nil
        if addingAccount?.slot == onboarding.slot { cancelAddingAccount() }
    }

    // MARK: - Onboarding

    /// The managed account of the onboarding's slot: device keys made on this device (Secure Enclave
    /// when present), then the account whose genesis names the org (and, for a join, the invited
    /// account id). The keys move under the account id on success and go on failure.
    func createManagedAccount(password: SecretBytes, displayName: String, mode: DeviceMode) async throws -> SecretBytes {
        guard let onboarding = managedOnboarding, let vault = accounts.session(for: onboarding.slot) else {
            throw VaultError.notFound
        }
        let orgID: String
        let accountID: String?
        switch onboarding.route {
        case .create:
            guard let draft = orgDraft else { throw VaultError.notFound }
            (orgID, accountID) = (draft.orgId(), nil)
        case .join(let invite):
            (orgID, accountID) = (invite.orgId, invite.accountId)
        }
        let keychain = vault.environment.keychain
        let pending = try ManagedDeviceKeys.createPending(keychain: keychain, slot: onboarding.slot)
        do {
            let secretKey = try await vault.createManagedAccount(
                password: password, displayName: displayName, mode: mode, orgID: orgID, accountID: accountID,
                keys: pending)
            guard let made = vault.environment.settings.accountID else { throw VaultError.notFound }
            try ManagedDeviceKeys.adoptPending(keychain: keychain, slot: onboarding.slot, accountID: made)
            // The join's org session was made before the account (to pin): remade with its keys.
            orgSessions[onboarding.slot] = nil
            return secretKey
        } catch {
            ManagedDeviceKeys.discardPending(keychain: keychain, slot: onboarding.slot)
            throw error
        }
    }

    /// After the account exists, in the background: a creation publishes the org and mints the token
    /// of the creator's own mailbox; then the account mailbox is made on the org server; a join then
    /// posts its request, with `password` (the one just typed) as the presence check (R31).
    func finishManagedOnboarding(secretKey: SecretBytes, password: SecretBytes? = nil) async {
        guard let onboarding = managedOnboarding else { return }
        defer { if managedOnboarding == onboarding { managedOnboarding = nil } }
        let slot = onboarding.slot
        guard let vault = accounts.session(for: slot) else { return }
        let settings = vault.environment.settings
        let credentials = ManagedOrgCredentials(keychain: vault.environment.keychain, slot: slot)
        if case .create(let name, let serverInvite) = onboarding.route {
            guard await publishOrg(slot: slot, name: name, serverInvite: serverInvite) else { return }
        }
        await runManagedMailboxSetup(slot, secretKey: secretKey)
        if case .join = onboarding.route, let org = orgSession(for: slot) {
            await ManagedAccountResume.run(
                settings: settings, org: org, credentials: credentials, displayName: settings.displayName,
                password: password)
        }
    }

    /// The org of a creation: published with the account's session and device keys, the org mailbox
    /// credential kept as this account's own, then a member token for its own mailbox. A failure
    /// leaves the creation unfinished (not resumed, plan deviation 15).
    private func publishOrg(slot: String, name: String, serverInvite: String) async -> Bool {
        guard let vault = accounts.session(for: slot), let draft = orgDraft,
            case .managed(let serverURL, _)? = accounts.profile(slot)?.kind,
            let accountID = vault.environment.settings.accountID
        else { return false }
        let keychain = vault.environment.keychain
        let settings = vault.environment.settings
        do {
            let pair = try ManagedDeviceKeys(keychain: keychain, accountID: accountID).deviceKeys()
            var created = try await vault.publishOrg(
                draft, endpoint: FfiMailboxEndpoint(baseUrl: serverURL, extraCaPem: nil), serverInvite: serverInvite,
                keys: pair, name: name, stateDir: Self.orgStateDirectory(vault).path)
            settings.orgMailboxID = created.mailboxId
            let credentials = ManagedOrgCredentials(keychain: keychain, slot: slot)
            try credentials.storeOwnSeed(SecretBytes(taking: &created.credentialSeed), orgMailboxID: created.mailboxId)
            orgDraft = nil
            guard let backend = orgBackend(for: slot) else { return false }
            let token = try await backend.mintMemberToken()
            defer { token.wipe() }
            try credentials.storeMemberToken(token)
            await orgSession(for: slot)?.load()
            return true
        } catch {
            Self.orgLog.error("organisation not published")
            showToast(VaultError(error).localizedMessage, kind: .error)
            return false
        }
    }

    // MARK: - Unlock

    /// At an unlock of a managed account: a mailbox setup cut off resumes, then a join request not
    /// posted yet is posted (once). An unfinished creation is only shown.
    func resumeManagedAccount(_ slot: String) async {
        guard managedOnboarding?.slot != slot, let vault = accounts.session(for: slot), vault.state == .unlocked
        else { return }
        let settings = vault.environment.settings
        guard settings.orgMailboxID != nil, let accountID = settings.accountID else { return }
        if !(await hasManagedMailbox(vault)),
            let key = try? SecretKeyVault(keychain: vault.environment.keychain).loadBytes(accountID: accountID)
        {
            await runManagedMailboxSetup(slot, secretKey: key)
            key.wipe()
        }
        guard let org = orgSession(for: slot) else { return }
        await ManagedAccountResume.run(
            settings: settings, org: org,
            credentials: ManagedOrgCredentials(keychain: vault.environment.keychain, slot: slot),
            displayName: settings.displayName)
    }

    private func hasManagedMailbox(_ vault: VaultSession) async -> Bool {
        guard let store = try? openSyncStore(dbPath: vault.environment.databaseURL.path),
            case .mailbox? = try? await SyncBackendState.read(store: store)
        else { return false }
        return true
    }

    /// The account mailbox of a managed slot on its org server (R32): the slot's own sync store and
    /// setup, made with the slot's member token (minted again by a creator that lost it), then handed
    /// to the slot's `ManagedAccountSync`. Offline, it resumes at the next unlock.
    private func runManagedMailboxSetup(_ slot: String, secretKey: SecretBytes) async {
        guard let vault = accounts.session(for: slot), let kind = accounts.profile(slot)?.kind,
            case .managed(let serverURL, _) = kind, OrgServers.isUsable(kind), let url = URL(string: serverURL)
        else {
            Self.orgLog.error("managed account without a usable server")
            return
        }
        let databaseURL = vault.environment.databaseURL
        let keychain = vault.environment.keychain
        let credentials = ManagedOrgCredentials(keychain: keychain, slot: slot)
        guard let store = try? openSyncStore(dbPath: databaseURL.path) else { return }
        var token = try? credentials.memberToken()
        if token == nil, vault.environment.settings.orgCreator, let backend = orgBackend(for: slot) {
            token = try? await backend.mintMemberToken()
            if let token { try? credentials.storeMemberToken(token) }
        }
        defer { token?.wipe() }
        let setup = MailboxSetup(
            provisioning: FfiMailboxProvisioning(databasePath: databaseURL.path),
            credentials: MailboxCredentialStore(keychain: keychain), store: store, hosted: nil, memberToken: token)
        guard let outcome = await vault.runMailboxSetup(
            setup, choice: .selfHost(url: url, extraCAPEM: nil), secretKey: secretKey)
        else { return }
        switch outcome {
        case .ready(let home):
            try? credentials.deleteMemberToken()
            attachManagedMailbox(home: home, databaseURL: databaseURL, keychain: keychain, slot: slot)
        case .failed(let message):
            showToast(message, kind: .error)
        case .offline, .iCloud:
            break
        }
    }

    /// Hands the mailbox of `home` to the slot's managed sync and reloads the account on each change set.
    func attachManagedMailbox(home: MailboxHome, databaseURL: URL, keychain: any KeychainStore, slot: String) {
        let name = SyncBackendState.mailbox(home).displayName(hosted: MailboxEndpoints.hosted())
        guard let sync = accountLink.managedSyncs[slot],
            let coordinator = Self.openMailbox(home: home, databaseURL: databaseURL, keychain: keychain, serverName: name)
        else { return }
        let task = Task { [weak self] in
            for await _ in await coordinator.remoteChanges() {
                guard let self else { return }
                await self.accounts.session(for: slot)?.reload()
                if self.accounts.activeSlot == slot { self.remoteRevision &+= 1 }
            }
        }
        accountTasks[slot, default: []].append(task)
        Task { await sync.attach(coordinator) }
    }

    // MARK: - Org session

    /// The org session of a managed slot, made on first use once its org mailbox is known.
    func orgSession(for slot: String) -> OrgSession? {
        if let made = orgSessions[slot] { return made }
        guard let vault = accounts.session(for: slot), let backend = orgBackend(for: slot) else { return nil }
        let keys = ManagedDeviceKeys(
            keychain: vault.environment.keychain, accountID: vault.environment.settings.accountID ?? "")
        let org = ManagedAccountResume.session(vault: vault, backend: backend, keys: keys)
        orgSessions[slot] = org
        return org
    }

    /// The org client of a managed slot: the member's own credential once it works, else the link's.
    private func orgBackend(for slot: String) -> ManagedOrgBackend? {
        if let made = orgBackends[slot] { return made }
        guard case .managed(let serverURL, let orgID)? = accounts.profile(slot)?.kind,
            let vault = accounts.session(for: slot), let mailboxID = vault.environment.settings.orgMailboxID
        else { return nil }
        let endpoint = FfiMailboxEndpoint(baseUrl: serverURL, extraCaPem: nil)
        let stateDir = Self.orgStateDirectory(vault).path
        let backend = ManagedOrgBackend(
            credentials: ManagedOrgCredentials(keychain: vault.environment.keychain, slot: slot),
            orgMailboxID: mailboxID
        ) { seed in
            try OrgClient.open(
                endpoint: endpoint, mailboxId: mailboxID, credentialSeed: seed, orgId: orgID, stateDir: stateDir)
        }
        orgBackends[slot] = backend
        return backend
    }

    /// Where the org pin of a slot lives: beside its store, in the slot folder.
    private static func orgStateDirectory(_ vault: VaultSession) -> URL {
        vault.environment.databaseURL.deletingLastPathComponent().appendingPathComponent("org", isDirectory: true)
    }
}
