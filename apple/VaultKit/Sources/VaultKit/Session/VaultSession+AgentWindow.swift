import Foundation
import OnePassCore

/// The agents-only window of the Mac (agent-ready spec 6.3): a session opened from the iPhone that
/// only the MCP and SSH servers use. For everything else the vault stays locked: `state` stays
/// `locked`, `coreSession` stays nil and `coreSessionChanged` is never told, so the app, AutoFill,
/// the browser extensions, the widgets, the companion, the password change and the exports all see
/// a locked vault and ask Touch ID or the password.
extension VaultSession {
    /// Opens the window on `session` (agents-only, from `RemoteUnlocker.finish`). Refused (and the
    /// session locked) unless the vault is locked with no window open.
    func openAgentWindow(_ session: Session, endsAt: Date) -> Bool {
        guard state == .locked, agentSession == nil, session.isAgentOnly() else {
            releaseAgentSession(session)
            return false
        }
        agentSession = session
        agentWindowEndsAt = endsAt
        return true
    }

    /// Ends the window, if one is open: the session is locked (keys dropped by the core, as on a
    /// normal lock) and `agentWindowEnded` is told.
    func endAgentWindow() {
        guard let session = agentSession else { return }
        agentSession = nil
        agentWindowEndsAt = nil
        releaseAgentSession(session)
        agentWindowEnded?()
    }

    /// The Account Unlock Key, behind Touch ID (spec 6.1 step 1), for a remote unlock enrollment.
    /// Unlocked vault with biometric unlock enrolled only; the caller wipes it.
    func accountKeyWithTouchID(prompt: String) async throws -> SecretBytes {
        guard state == .unlocked else { throw fail(.passwordRequired) }
        guard canUseBiometrics, let accountID = settings.accountID else { throw fail(.biometricsUnavailable) }
        let gen = generation
        do {
            var auk = try await biometrics.unlock(accountID: accountID, prompt: prompt)
            let key = SecretBytes(taking: &auk)
            guard gen == generation, state == .unlocked else {
                key.wipe()
                throw VaultError.passwordRequired
            }
            return key
        } catch {
            biometricsRevision += 1
            throw fail(VaultError(error))
        }
    }
}
