import Foundation
import LocalAuthentication

/// Asks the device owner to confirm their presence (Face ID, Touch ID, Apple Watch or the device
/// passcode) before a `reprompt` item shows its secrets. Unlocks nothing: no key is involved.
public protocol PresenceChecker: Sendable {
    /// True when confirmed; false when cancelled, failed or impossible (the caller then asks
    /// for the master password).
    func confirm(prompt: String) async -> Bool
    /// Face ID or Touch ID only, never the device passcode: approving or revoking a device (ruling
    /// A8, L4). False when cancelled, failed, impossible or when the user asks for the fallback: the
    /// caller then asks for the master password.
    func confirmWithBiometrics(prompt: String) async -> Bool
}

extension PresenceChecker {
    /// Fail closed: without a biometric check of its own, a checker sends the user to the master
    /// password.
    public func confirmWithBiometrics(prompt: String) async -> Bool { false }
}

/// `LAContext` with `.deviceOwnerAuthentication`.
public struct SystemPresenceChecker: PresenceChecker {
    public init() {}

    public func confirm(prompt: String) async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return false }
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: prompt)
        } catch {
            return false
        }
    }

    /// `LAContext` with `.deviceOwnerAuthenticationWithBiometrics`: the passcode is never offered; the
    /// fallback button leads to the master password.
    public func confirmWithBiometrics(prompt: String) async -> Bool {
        let context = LAContext()
        context.localizedFallbackTitle = String(localized: "Utiliser le mot de passe maître", bundle: VaultKitStrings.bundle)
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { return false }
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: prompt)
        } catch {
            return false
        }
    }
}
