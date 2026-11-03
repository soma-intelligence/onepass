import Foundation
import LocalAuthentication
import OnePassCore
import os

/// The vault of the iOS Safari Web Extension (spec 2026-11-03-ios-safari-autofill): the handler
/// process opens its own `VaultSession` on the shared store, unlocks it from the unlock sheet (Face ID
/// or Touch ID under the app's biometric policy, or the master password) and serves the bridge on it
/// in this process (`BridgeServer.connectInProcess`, ruling I1). The session dies with the process
/// (ruling I3) and locks itself after the app's auto-lock delay without a request, at most 15 minutes.
///
/// Anti-loop rule: a biometric attempt never starts while another runs, and never within
/// `biometricGap` of the end of the previous one. The sheet adds its own rule (one automatic try per
/// presentation, the explicit button after).
@MainActor
public final class SafariExtensionVault {
    /// What the unlock sheet shows. No secret, no item data.
    public struct State: Equatable, Sendable {
        public var locked: Bool
        /// The account's display name, or empty.
        public var account: String
        /// `faceID`, `touchID`, `opticID`, or `none` when biometric unlock cannot be used now.
        public var biometry: String
        public var failure: Failure?
        /// Why the master password is needed, in the user's language.
        public var message: String?

        public init(
            locked: Bool, account: String, biometry: String, failure: Failure? = nil, message: String? = nil
        ) {
            self.locked = locked
            self.account = account
            self.biometry = biometry
            self.failure = failure
            self.message = message
        }
    }

    /// Stable codes the sheet turns into its own words.
    public enum Failure: String, Sendable {
        case passwordRequired = "password_required"
        case wrongPassword = "wrong_password"
        case cancelled
        case lockedOut = "locked_out"
        case noAccount = "no_account"
        case failed
    }

    /// Smallest pause between the end of a biometric attempt and the next one.
    public static let biometricGap: TimeInterval = 1.5
    /// Longest the vault stays open without a request, whatever the app's setting.
    public static let maxIdle: TimeInterval = 15 * 60

    public let session: VaultSession
    private let server: BridgeServer
    private let biometryKind: @Sendable () -> String
    private let now: @Sendable () -> Date
    private var biometricRunning = false
    private var lastBiometricEnd: Date?
    private var lastActivity: Date
    private var idleTask: Task<Void, Never>?

    nonisolated static let log = Logger(subsystem: "me.somalabs.onepass", category: "safari-vault")

    /// `pairingKeychain`: where the bridge pairings live (the shared keychain group by default, the
    /// same item as the Mac app's). `biometryKind` and `now`: tests pass their own.
    public init(
        environment: VaultEnvironment, pairingKeychain: (any KeychainStore)? = nil,
        biometryKind: (@Sendable () -> String)? = nil, now: @escaping @Sendable () -> Date = { Date() }
    ) {
        let session = VaultSession(environment: environment)
        self.session = session
        self.now = now
        self.lastActivity = now()
        self.biometryKind = biometryKind ?? Self.systemBiometryKind
        let keychain =
            pairingKeychain
            ?? SystemKeychain(service: BridgePairingStore.service, accessGroup: VaultEnvironment.sharedAccessGroup())
        let store = BridgePairingStore(keychain: keychain)
        let delegate = Delegate(store: store)
        let server = BridgeServer(
            delegate: delegate, pairings: store.load(), allowedExtensions: [],
            auditPath: environment.databaseURL.deletingLastPathComponent()
                .appendingPathComponent("bridge-audit.jsonl").path)
        server.setBlockedAuto(extensionIds: store.blockedAuto())
        self.server = server
        delegate.owner = self
        let account = environment.settings.displayName
        session.coreSessionChanged = { [weak server] core in
            server?.setSession(session: core, accountName: account.isEmpty ? "OnePass" : account)
        }
        session.hiddenVaultsChanged = { [weak server] ids in
            try? server?.setExcludedVaults(vaultIds: ids.sorted())
        }
        try? server.setExcludedVaults(vaultIds: session.hiddenVaultIDs.sorted())
    }

    /// The caller's end of a new bridge connection served in this process (the caller owns it).
    /// Callable from any thread.
    nonisolated public func connect() throws -> Int32 {
        try server.connectInProcess()
    }

    /// For the sheet: locked or not, the account, which biometry can be used now.
    public func state(failure: Failure? = nil, message: String? = nil) -> State {
        noteActivity()
        let account = session.environment.settings.displayName
        if session.state == .noAccount {
            return State(locked: true, account: "", biometry: "none", failure: failure ?? .noAccount)
        }
        return State(
            locked: session.state != .unlocked, account: account,
            biometry: session.canUseBiometrics ? biometryKind() : "none", failure: failure, message: message)
    }

    /// Face ID or Touch ID. Refused without a prompt while another attempt runs or right after one
    /// ended (`biometricGap`). A policy refusal (reboot, 14 days, biometry changed) ends with
    /// `passwordRequired` and no biometry offered; a cancel keeps the button.
    public func unlockWithBiometrics() async -> State {
        if session.state == .unlocked { return state() }
        if biometricRunning { return state(failure: .cancelled) }
        if let end = lastBiometricEnd, now().timeIntervalSince(end) < Self.biometricGap {
            return state(failure: .cancelled)
        }
        guard session.canUseBiometrics else {
            return state(failure: .passwordRequired, message: PasswordReason.notEnrolled.message)
        }
        biometricRunning = true
        defer {
            biometricRunning = false
            lastBiometricEnd = now()
        }
        do {
            try await session.unlockWithBiometrics()
            Self.log.notice("unlocked with biometrics")
            scheduleIdleLock()
            return state()
        } catch {
            if session.state == .unlocked { return state() }
            if session.canUseBiometrics { return state(failure: .cancelled) }
            Self.log.notice("biometrics refused by the policy: password asked")
            return state(failure: .passwordRequired, message: Self.message(for: error))
        }
    }

    /// The master password from the sheet. The caller wipes `password`.
    public func unlock(password: SecretBytes) async -> State {
        if session.state == .unlocked { return state() }
        do {
            try await session.unlock(password: password)
            Self.log.notice("unlocked with the master password")
            scheduleIdleLock()
            return state()
        } catch let error as VaultError {
            switch error {
            case .wrongPassword: return state(failure: .wrongPassword)
            case .lockedOut: return state(failure: .lockedOut, message: Self.message(for: error))
            default: return state(failure: .failed, message: Self.message(for: error))
            }
        } catch {
            return state(failure: .failed)
        }
    }

    /// A request came in: the idle clock starts again.
    public func noteActivity() {
        lastActivity = now()
    }

    /// Locks after the app's auto-lock delay (capped at `maxIdle`) without a request.
    private func scheduleIdleLock() {
        idleTask?.cancel()
        let delay = min(session.environment.settings.effectiveAutoLockSeconds ?? Self.maxIdle, Self.maxIdle)
        idleTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(max(delay / 4, 5)))
                guard let self, self.session.state == .unlocked else { return }
                if self.now().timeIntervalSince(self.lastActivity) >= delay {
                    Self.log.notice("idle: locked")
                    self.session.lock()
                    return
                }
            }
        }
    }

    static func message(for error: any Error) -> String? {
        (error as? VaultError)?.localizedMessage
    }

    nonisolated static func systemBiometryKind() -> String {
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else { return "none" }
        switch context.biometryType {
        case .faceID: return "faceID"
        case .touchID: return "touchID"
        case .opticID: return "opticID"
        default: return "none"
        }
    }

    // MARK: - Bridge callbacks

    fileprivate func wroteVault() async {
        await session.bridgeWroteVault()
        await session.publishAutofillIdentitiesNow()
    }

    fileprivate func confirmReprompt() async -> Bool {
        let prompt = String(localized: "bridge.fillProtectedItem", bundle: VaultKitStrings.bundle)
        return await session.confirmUserPresence(prompt: prompt)
    }

    /// Called on Rust bridge threads; every vault step hops to the main actor.
    private final class Delegate: BridgeDelegate, @unchecked Sendable {
        weak var owner: SafariExtensionVault?
        let store: BridgePairingStore

        init(store: BridgePairingStore) {
            self.store = store
        }

        /// iOS pairs only automatically (ruling I2): there is no sheet to show a code on.
        func pairingRequested(request: FfiBridgePairingRequest) {}
        func pairingEnded(requestId: UInt64) {}

        func pairingStored(pairing: FfiBridgePairing) {
            store.add(pairing)
            SafariExtensionVault.log.notice("pairing stored")
        }

        func pairingUsed(pairingId: String, at: UInt64) {
            store.touch(pairingId, at: at)
            Task { @MainActor [weak owner] in owner?.noteActivity() }
        }

        /// The sheet unlocks on iOS; the bridge's `unlock` only reports the state.
        func unlockRequested() {}

        /// Blocks this bridge thread (never the main one) until Face ID answers, at most 2 min.
        func confirmReprompt(vaultId: String, itemId: String) -> Bool {
            let done = DispatchSemaphore(value: 0)
            let answer = Answer()
            Task { @MainActor [weak owner] in
                answer.value = await owner?.confirmReprompt() ?? false
                done.signal()
            }
            guard done.wait(timeout: .now() + 120) == .success else { return false }
            return answer.value
        }

        func vaultChanged() {
            Task { @MainActor [weak owner] in await owner?.wroteVault() }
        }

        func note(message: String) {
            SafariExtensionVault.log.notice("\(message, privacy: .public)")
        }
    }

    private final class Answer: @unchecked Sendable {
        var value = false
    }
}
