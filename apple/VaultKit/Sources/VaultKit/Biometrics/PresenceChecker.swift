import Foundation
import LocalAuthentication

/// Asks the device owner to confirm their presence (Face ID, Touch ID, Apple Watch or the device
/// passcode) before a `reprompt` item shows its secrets. Unlocks nothing: no key is involved.
public protocol PresenceChecker: Sendable {
    /// True when confirmed; false when cancelled, failed or impossible (the caller then asks
    /// for the master password).
    func confirm(prompt: String) async -> Bool
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
}
