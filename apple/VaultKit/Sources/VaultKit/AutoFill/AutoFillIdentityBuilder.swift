import AuthenticationServices
import Foundation

/// Turns the core's AutoFill identities into the system's credential identities (QuickType
/// suggestions, passkey sheet). Only metadata: host, user name, record id, passkey credential id and
/// user handle (ruling A8). Never a password, a code or a key.
public enum AutoFillIdentityBuilder {
    /// Service identifiers are domains (`.domain`). The rank is the core's (`FfiAutofillIdentity.rank`:
    /// the Login used last on the site first, then favorites): the system shows a higher rank first
    /// for the same service.
    public static func credentialIdentities(_ identities: [FfiAutofillIdentity]) -> [any ASCredentialIdentity] {
        identities.map { identity -> any ASCredentialIdentity in
            let service = ASCredentialServiceIdentifier(identifier: identity.service, type: .domain)
            let built: any ASCredentialIdentity
            switch identity.kind {
            case .password:
                built = ASPasswordCredentialIdentity(
                    serviceIdentifier: service, user: identity.user, recordIdentifier: identity.recordId)
            case .oneTimeCode:
                built = ASOneTimeCodeCredentialIdentity(
                    serviceIdentifier: service, label: identity.user.isEmpty ? identity.service : identity.user,
                    recordIdentifier: identity.recordId)
            case .passkey:
                built = ASPasskeyCredentialIdentity(
                    relyingPartyIdentifier: identity.service, userName: identity.user,
                    credentialID: identity.credentialId, userHandle: identity.userHandle,
                    recordIdentifier: identity.recordId)
            }
            built.rank = Int(identity.rank)
            return built
        }
    }
}
