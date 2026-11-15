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
    /// The member's name typed in "Join an organisation" (`confirmOrgJoin`): the onboarding takes it.
    var displayName: String?
}

/// A join under way: the managed slot `beginOrgJoin` made and the organisation it pinned there.
struct OrgJoinStart: Equatable {
    let slot: String
    let state: FfiOrgState
}

/// The name and colour of a managed account, chosen in "Add an account".
struct OrgAccountLook: Equatable {
    let label: String
    let color: FfiAccountColor
}

/// The organisation sheets the root shows: joining (an invitation, or the field to paste one) and
/// creating (Mac and iPad).
enum OrgSheet: Identifiable, Equatable {
    case join(FfiOrgInvite?, OrgAccountLook?)
    case create(OrgAccountLook?)

    var id: String {
        switch self {
        case .join: "join"
        case .create: "create"
        }
    }
}

extension AppModel {
    private static var orgLog: Logger { Logger(subsystem: "me.somalabs.onepass", category: "org") }

    // MARK: - Starting

    /// Starts a new organisation: its draft (the org id), a managed slot on `serverURL`, then the sign
    /// up of the onboarding on that slot. Nothing reaches the server before the account exists.
    func beginOrgCreation(name: String, serverURL: URL, serverInvite: String, look: OrgAccountLook? = nil)
        throws(AccountsError)
    {
        let draft: OrgDraft
        do {
            draft = try OrgDraft()
        } catch {
            throw .directory(VaultError(error))
        }
        let kind = FfiAccountKind.managed(serverUrl: serverURL.absoluteString, orgId: draft.orgId())
        try beginAddingAccount(
            kind: kind, label: Self.label(look, default: name), color: look?.color ?? .indigo, signIn: false)
        let slot = accounts.activeSlot
        accounts.session(for: slot)?.environment.settings.orgCreator = true
        orgDraft = draft
        managedOnboarding = ManagedOnboarding(slot: slot, route: .create(name: name, serverInvite: serverInvite))
    }

    /// Starts joining the organisation of `invite`: the pin plan (MDM, DNS, else first use), a managed
    /// slot, the link's secrets in the keychain, then the pin, before the account exists. Any failure
    /// takes the slot out again. The caller keeps the slot to cancel that join only (`cancelOrgJoin(slot:)`).
    func beginOrgJoin(_ invite: FfiOrgInvite, look: OrgAccountLook? = nil) async throws(OrgActionError)
        -> OrgJoinStart
    {
        let plan = await OrgPinResolver(mdm: ManagedOrgConfig.read(), dns: SystemDNSTXTResolver()).plan(for: invite)
        // Refused before any slot exists, each refusal with what to do about it.
        if case .refuse(let reason) = plan { throw .other(reason.message) }
        let kind = FfiAccountKind.managed(serverUrl: invite.serverUrl, orgId: invite.orgId)
        do {
            try beginAddingAccount(
                kind: kind, label: Self.label(look, default: invite.domain ?? ""), color: look?.color ?? .indigo,
                signIn: false)
        } catch {
            throw .other(error.message)
        }
        let slot = accounts.activeSlot
        managedOnboarding = ManagedOnboarding(slot: slot, route: .join(invite))
        do throws(OrgActionError) {
            return OrgJoinStart(slot: slot, state: try await pinJoinedOrg(invite, plan: plan, slot: slot))
        } catch {
            cancelOrgJoin(slot: slot)
            throw error
        }
    }

    /// The member's name typed in "Join an organisation": kept on the slot and handed to the
    /// onboarding under the sheet, which signs the member up next.
    func confirmOrgJoin(slot: String, displayName: String) {
        guard managedOnboarding?.slot == slot else { return }
        accounts.session(for: slot)?.environment.settings.displayName = displayName
        managedOnboarding?.displayName = displayName
    }

    /// The account's name: the one chosen in "Add an account", else `fallback`.
    private static func label(_ look: OrgAccountLook?, default fallback: String) -> String {
        guard let chosen = look?.label, !chosen.isEmpty else { return fallback }
        return chosen
    }

    // MARK: - Sheets

    /// Shows an organisation sheet at the root: the sheets the model owns close first (as for a
    /// verification code link), so it never stacks on Settings. An item being written keeps the sheet
    /// out (a message says so): the join or creation switches account, which would drop the edit.
    /// `afterSheet`: the caller's own sheet is closing (it is given the same time to leave).
    func presentOrgSheet(_ sheet: OrgSheet, afterSheet: Bool = false) async {
        guard newItemDraft == nil, !editing else {
            showToast(String(localized: "org.join.finishEditing"), kind: .error)
            return
        }
        let covered = afterSheet || showSettings || showAddAccount || showGenerator || showNewItemPicker
            || showImport || showOtpScanner || otpLinkRequest != nil || totpPasswordRequest != nil
            || orgSheet != nil
        totpPasswordRequest = nil
        showOtpScanner = false
        showSettings = false
        showAddAccount = false
        showGenerator = false
        showNewItemPicker = false
        showImport = false
        otpLinkRequest = nil
        orgSheet = nil
        if covered {
            try? await Task.sleep(for: .milliseconds(700))
        } else {
            await Task.yield()
        }
        guard session.state == .unlocked else { return }
        orgSheet = sheet
    }

    /// An `onepass://org/join` link once the vault is open: its invitation, or `org.join.badLink`.
    func openOrgJoinLink(_ link: String) async {
        guard let invite = try? orgInviteParse(link: link, allowLoopbackHttp: MailboxEndpoints.allowsLocalHTTP)
        else {
            showToast(String(localized: "org.join.badLink"), kind: .error)
            return
        }
        await presentOrgSheet(.join(invite, nil))
    }

    /// The join's settings and keychain items on `slot`, then the pin.
    private func pinJoinedOrg(_ invite: FfiOrgInvite, plan: OrgPinPlan, slot: String) async throws(OrgActionError)
        -> FfiOrgState
    {
        let missing = OrgActionError.other(VaultError.notFound.localizedMessage)
        guard let vault = accounts.session(for: slot) else { throw missing }
        let settings = vault.environment.settings
        settings.orgMailboxID = invite.mailboxId
        settings.orgDomain = invite.domain
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
        // Cancelled while the pin ran (its sheet closed): the slot is gone, its org objects go too.
        guard managedOnboarding?.slot == slot else {
            orgSessions[slot] = nil
            orgBackends[slot] = nil
            throw missing
        }
        guard let state = org.state else { throw missing }
        return state
    }

    /// Leaves the managed sign up of `slot` before its account exists (creation or join): the slot,
    /// its pending device keys and its org credentials go (`AccountSessions.discard`). Another slot's
    /// sign up under way is left alone; only `slot`'s org objects are dropped, and `slot` itself if
    /// it still has no account (a join a newer one replaced), so no directory entry is left behind.
    func cancelOrgJoin(slot: String) {
        orgSessions[slot] = nil
        orgBackends[slot] = nil
        guard managedOnboarding?.slot == slot else {
            guard slot != accounts.activeSlot, addingAccount?.slot != slot,
                let profile = accounts.profile(slot), profile.accountID == nil,
                accounts.session(for: slot)?.environment.settings.accountID == nil
            else { return }
            stopAccountTasks(slot)
            forgetAccountLinks(slot)
            accounts.cancelAdding(slot)
            return
        }
        managedOnboarding = nil
        orgDraft = nil
        if addingAccount?.slot == slot { cancelAddingAccount() }
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
        let secretKey: SecretBytes
        do {
            secretKey = try await vault.createManagedAccount(
                password: password, displayName: displayName, mode: mode, orgID: orgID, accountID: accountID,
                keys: pending)
        } catch {
            // No account names these keys: they go. Past this point the account exists and its keys
            // stay (pending ones are adopted at the next try or removed with the slot).
            ManagedDeviceKeys.discardPending(keychain: keychain, slot: onboarding.slot)
            throw error
        }
        guard let made = vault.environment.settings.accountID else { throw VaultError.notFound }
        try ManagedDeviceKeys.adoptPending(keychain: keychain, slot: onboarding.slot, accountID: made)
        // The join's org session was made before the account (to pin): remade with its keys.
        orgSessions[onboarding.slot] = nil
        return secretKey
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
        await runManagedMailboxSetup(slot, secretKey: secretKey, quiet: false)
        guard case .join = onboarding.route, let org = orgSession(for: slot) else { return }
        guard let password else {
            await ManagedAccountResume.run(
                settings: settings, org: org, credentials: credentials, displayName: settings.displayName)
            return
        }
        do {
            try await ManagedAccountResume.sendJoinRequest(
                settings: settings, org: org, credentials: credentials, displayName: settings.displayName,
                password: password)
        } catch {
            // Posted again at the next unlock.
            Self.orgLog.error("join request not posted in the onboarding")
        }
    }

    /// Posts the join request of `slot` that waits for a presence check (`orgJoinWaiting`, R34), with
    /// the master password the user typed. False: nothing was posted (no pending request, or the org
    /// is not readable yet), nothing thrown.
    func sendJoinRequest(slot: String, password: SecretBytes) async throws(OrgActionError) -> Bool {
        guard let vault = accounts.session(for: slot), let org = orgSession(for: slot) else {
            throw .other(VaultError.notFound.localizedMessage)
        }
        let settings = vault.environment.settings
        return try await ManagedAccountResume.sendJoinRequest(
            settings: settings, org: org,
            credentials: ManagedOrgCredentials(keychain: vault.environment.keychain, slot: slot),
            displayName: settings.displayName, password: password)
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
            // The unfinished org made before the publish: remade on the org mailbox.
            orgSessions[slot] = nil
            orgBackends[slot] = nil
            guard let backend = orgBackend(for: slot) as? ManagedOrgBackend else { return false }
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
            await runManagedMailboxSetup(slot, secretKey: key, quiet: true)
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
    /// setup (its own pending seed slot), made with the slot's member token (`ManagedMailboxSetup`:
    /// a creator mints again once, a refused joiner is flagged), then handed to the slot's
    /// `ManagedAccountSync`. Offline, it resumes at the next unlock. `quiet` (at unlock): no toast.
    private func runManagedMailboxSetup(_ slot: String, secretKey: SecretBytes, quiet: Bool) async {
        guard let vault = accounts.session(for: slot), let kind = accounts.profile(slot)?.kind,
            case .managed(let serverURL, _) = kind, OrgServers.isUsable(kind), let url = URL(string: serverURL)
        else {
            Self.orgLog.error("managed account without a usable server")
            return
        }
        let databaseURL = vault.environment.databaseURL
        let keychain = vault.environment.keychain
        let settings = vault.environment.settings
        guard let store = try? openSyncStore(dbPath: databaseURL.path) else { return }
        let mint: (@MainActor () async throws -> SecretBytes)?
        if settings.orgCreator, let backend = orgBackend(for: slot) as? ManagedOrgBackend {
            mint = { try await backend.mintMemberToken() }
        } else {
            mint = nil
        }
        let outcome = await ManagedMailboxSetup.run(
            settings: settings, credentials: ManagedOrgCredentials(keychain: keychain, slot: slot), mint: mint,
            makeSetup: { token in
                MailboxSetup(
                    provisioning: FfiMailboxProvisioning(databasePath: databaseURL.path),
                    credentials: MailboxCredentialStore(keychain: keychain), store: store, hosted: nil,
                    memberToken: token, managed: true, pendingCredentialID: MailboxSetup.pendingCredentialID(slot: slot))
            },
            perform: { setup in
                await vault.runMailboxSetup(setup, choice: .selfHost(url: url, extraCAPEM: nil), secretKey: secretKey)
            })
        switch outcome {
        case .ready(let home)?:
            attachManagedMailbox(home: home, databaseURL: databaseURL, keychain: keychain, slot: slot)
        case .failed(let message)?:
            if !quiet { showToast(message, kind: .error) }
        case .tokenRefused?, .offline?, .iCloud?, nil:
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

    /// The org session Réglages > Organisation shows: the active account's, when it is managed.
    var shownOrgSession: OrgSession? {
        #if DEBUG
        if let demoOrgSession { return demoOrgSession }
        #endif
        guard case .managed? = accounts.activeProfile?.kind else { return nil }
        return orgSession(for: accounts.activeSlot)
    }

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

    /// The org client of a managed slot: the member's own credential once it works, else the link's;
    /// a creation cut off before its publish gets `UnfinishedOrgBackend` (`ManagedAccountResume.backend`).
    private func orgBackend(for slot: String) -> (any OrgBackend)? {
        if let made = orgBackends[slot] { return made }
        guard case .managed(let serverURL, let orgID)? = accounts.profile(slot)?.kind,
            let vault = accounts.session(for: slot)
        else { return nil }
        let settings = vault.environment.settings
        let endpoint = FfiMailboxEndpoint(baseUrl: serverURL, extraCaPem: nil)
        let stateDir = Self.orgStateDirectory(vault).path
        let mailboxID = settings.orgMailboxID ?? ""
        let backend = ManagedAccountResume.backend(
            settings: settings, credentials: ManagedOrgCredentials(keychain: vault.environment.keychain, slot: slot)
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
