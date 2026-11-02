import DesignKit
import SwiftUI
import VaultKit
import os

/// What ties the account sessions to the app model: made before the model exists (the environment
/// factory of `AccountSessions` is built in the model's `init`), told the model at the end of it.
@MainActor
final class AccountModelLink {
    weak var model: AppModel?
    /// The sync of each added account, by slot.
    var syncs: [String: AccountSync] = [:]
}

/// An account being added: its slot, the account shown before, and whether the user signs in to an
/// account that exists (else creates one).
struct AddingAccount: Equatable {
    let slot: String
    let previous: String
    let signIn: Bool
}

extension AppModel {
    private static var accountsLog: Logger { Logger(subsystem: "me.somalabs.onepass", category: "accounts") }

    /// The environment of an added account: the primary environment (keychain, biometrics, clock,
    /// pasteboard, presence) with the account's store, its settings scope and its own sync. Nothing of it
    /// is published to the system identity store (ruling P6).
    static func accountEnvironment(
        primary: VaultEnvironment, remote: (any RemoteRecordStore)?, containerIdentifier: String,
        link: AccountModelLink
    ) -> AccountSessions.EnvironmentFactory {
        { slot, url, settings in
            var environment = primary
            environment.databaseURL = url
            environment.settings = settings
            environment.identityStore = NoIdentityStore()
            #if ONEPASS_CLOUDKIT
            if remote != nil {
                let path = url.path
                let sync = AccountSync(
                    syncsWithServer: true,
                    make: { accountID in
                        guard let store = try? openSyncStore(dbPath: path) else { return nil }
                        return SyncCoordinator(
                            store: store,
                            remote: CloudKitRemote(
                                containerIdentifier: containerIdentifier,
                                zoneName: CloudKitMapping.zoneName(forAccount: accountID)))
                    },
                    made: { coordinator in
                        Task { @MainActor in link.model?.listen(to: coordinator, slot: slot) }
                    })
                link.syncs[slot] = sync
                environment.sync = sync
            } else {
                environment.sync = NoSync()
            }
            #else
            environment.sync = NoSync()
            #endif
            return environment
        }
    }

    /// Reloads an added account's session after each change set of its zone.
    func listen(to coordinator: SyncCoordinator, slot: String) {
        let task = Task { [weak self] in
            for await _ in await coordinator.remoteChanges() {
                guard let self else { return }
                await self.accounts.session(for: slot)?.reload()
                if self.accounts.activeSlot == slot { self.remoteRevision &+= 1 }
            }
        }
        accountTasks[slot, default: []].append(task)
        Task { await coordinator.syncNow() }
    }

    /// The sync coordinator of the account shown. An added account has one once its account is known;
    /// `forSignIn` while signing in to an account on a new device: the first iCloud zone of an account
    /// this device does not have yet (ruling P8).
    func activeCoordinator(forSignIn: Bool = false) async -> SyncCoordinator? {
        let slot = accounts.activeSlot
        if slot == AccountDirectoryStore.primarySlot { return coordinator }
        guard let sync = accountLink.syncs[slot] else { return nil }
        if let current = await sync.current { return current }
        guard forSignIn, addingAccount?.slot == slot, addingAccount?.signIn == true else { return nil }
        let known = Set(accounts.profiles.compactMap(\.accountID))
        guard let zones = try? await CloudKitRemote.accountZones(containerIdentifier: Self.cloudKitContainer),
            let candidate = zones.first(where: { !known.contains($0) })
        else { return nil }
        return await sync.attach(accountID: candidate)
    }

    // MARK: - Switching and locking

    /// Shows another account. The one left keeps its own lock delay (ruling P13).
    func switchAccount(to slot: String) {
        guard slot != accounts.activeSlot else { return }
        resetNavigation()
        dropPendingOtpLink()
        selection = .all
        page = .items
        do {
            try accounts.switchTo(slot)
        } catch {
            showToast(error.message, kind: .error)
            return
        }
        sessionStateChanged(session.state)
    }

    /// Every account of the device.
    func lockAll() {
        resetNavigation()
        dropPendingOtpLink()
        accounts.lockAll()
    }

    // MARK: - Adding

    /// Starts adding an account: its slot, then the sign up (or the Emergency Kit sign in) of the
    /// onboarding on that account. A managed account is refused while no server can hold it.
    func beginAddingAccount(kind: FfiAccountKind, label: String, color: FfiAccountColor, signIn: Bool)
        throws(AccountsError)
    {
        let previous = accounts.activeSlot
        let slot = try accounts.beginAdding(kind: kind, label: label, color: color)
        addingAccount = AddingAccount(slot: slot, previous: previous, signIn: signIn)
        switchAccount(to: slot)
        onboardingStart = signIn ? .restore : nil
        onboardingInProgress = true
    }

    /// The new account has no account yet: the user may still leave its sign up.
    var canCancelAddingAccount: Bool {
        guard let adding = addingAccount, accounts.activeSlot == adding.slot else { return false }
        return session.environment.settings.accountID == nil && session.state != .unlocked
    }

    /// Leaves the sign up of the new account: its slot goes, the account shown before comes back.
    func cancelAddingAccount() {
        guard let adding = addingAccount, canCancelAddingAccount else { return }
        addingAccount = nil
        onboardingInProgress = false
        onboardingStart = nil
        switchAccount(to: adding.previous)
        stopAccountTasks(adding.slot)
        accountLink.syncs[adding.slot] = nil
        accounts.cancelAdding(adding.slot)
    }

    /// The onboarding of the new account ended: its account is bound to its slot. The same account
    /// already on this device is refused (M5) and the account shown before comes back.
    func finishAddingAccountIfNeeded() {
        guard let adding = addingAccount else { return }
        guard accounts.session(for: adding.slot)?.environment.settings.accountID != nil else {
            // Left without an account (the onboarding closed on its own): nothing was added.
            if accounts.activeSlot == adding.slot { cancelAddingAccount() }
            addingAccount = nil
            return
        }
        addingAccount = nil
        do {
            try accounts.finishAdding(adding.slot)
        } catch {
            if error == .alreadyOnDevice {
                stopAccountTasks(adding.slot)
                accountLink.syncs[adding.slot] = nil
                switchAccount(to: adding.previous)
            }
            showToast(error.message, kind: .error)
        }
    }

    /// Takes an added account off this device (M8), after the user confirmed.
    func removeAccount(_ slot: String) {
        do {
            if accounts.activeSlot == slot { switchAccount(to: AccountDirectoryStore.primarySlot) }
            stopAccountTasks(slot)
            accountLink.syncs[slot] = nil
            try accounts.remove(slot)
            settingsChanged()
        } catch {
            showToast(error.message, kind: .error)
        }
    }

    private func stopAccountTasks(_ slot: String) {
        accountTasks[slot]?.forEach { $0.cancel() }
        accountTasks[slot] = nil
    }

    // MARK: - Look

    /// The profile of the account shown.
    var activeProfile: AccountProfile? { accounts.activeProfile }

    /// The color of the account shown (its avatar, its lock screen). A device with one account looks
    /// as before: the accent.
    var accountTint: Color {
        guard accounts.hasSeveralAccounts, let profile = activeProfile else { return Theme.accent }
        return AccountStyle.color(profile.color)
    }

    /// The kind badge of the account shown, none for a personal account.
    var accountBadge: String? { activeProfile.flatMap(AccountStyle.badge) }

    /// The name the apps show for an account: its label, else the profile name of its session.
    func displayName(of profile: AccountProfile) -> String {
        if !profile.label.isEmpty { return profile.label }
        let name = accounts.madeSession(profile.slot)?.environment.settings.displayName ?? ""
        return name.isEmpty ? String(localized: "accounts.name.default") : name
    }

    /// Initials of an account ("Soma Labs" gives "SL").
    func initials(of profile: AccountProfile) -> String {
        let source = profile.isPrimary || profile.label.isEmpty
            ? (accounts.madeSession(profile.slot)?.environment.settings.displayName ?? "") : profile.label
        let words = source.split(whereSeparator: { $0.isWhitespace || $0 == "-" })
        return words.prefix(2).compactMap { $0.first.map { String($0).uppercased() } }.joined()
    }
}

/// Colors and badges of the accounts (multi-account spec 7): the system palette, one per account.
enum AccountStyle {
    static func color(_ color: FfiAccountColor) -> Color {
        switch color {
        case .blue: .blue
        case .green: .green
        case .orange: .orange
        case .purple: .purple
        case .pink: .pink
        case .teal: .teal
        case .indigo: .indigo
        case .graphite: .gray
        }
    }

    static let palette: [FfiAccountColor] = [.blue, .green, .orange, .purple, .pink, .teal, .indigo, .graphite]

    /// The badge on the avatar of a non personal account: a briefcase, a building.
    static func badge(_ profile: AccountProfile) -> String? {
        switch profile.kind {
        case .personal: nil
        case .business: "briefcase.fill"
        case .managed: "building.2.fill"
        }
    }

    /// The color's name, for VoiceOver.
    static func colorName(_ color: FfiAccountColor) -> LocalizedStringKey {
        switch color {
        case .blue: "accounts.color.blue"
        case .green: "accounts.color.green"
        case .orange: "accounts.color.orange"
        case .purple: "accounts.color.purple"
        case .pink: "accounts.color.pink"
        case .teal: "accounts.color.teal"
        case .indigo: "accounts.color.indigo"
        case .graphite: "accounts.color.graphite"
        }
    }

    /// The kind as a short label.
    static func kindName(_ kind: FfiAccountKind) -> String {
        switch kind {
        case .personal: String(localized: "accounts.kind.personal")
        case .business: String(localized: "accounts.kind.business")
        case .managed: String(localized: "accounts.kind.managed")
        }
    }
}
