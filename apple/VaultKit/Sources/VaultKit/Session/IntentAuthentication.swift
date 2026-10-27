import Foundation

/// Ruling W13: a "Copier le code à usage unique" request is authenticated by an unlock only when
/// that unlock happens after the request. Decided when the request is queued, from the state then.
public enum IntentAuthentication {
    /// True when the request waits for an unlock the user has not started yet: locked, outside the
    /// onboarding. Unlocked, unlocking (started before the request), no account, failed, or during
    /// the onboarding: the unlock does not count and the user is confirmed again.
    public static func isFreshUnlockRequest(state: VaultSession.State, onboarding: Bool) -> Bool {
        !onboarding && state == .locked
    }
}
