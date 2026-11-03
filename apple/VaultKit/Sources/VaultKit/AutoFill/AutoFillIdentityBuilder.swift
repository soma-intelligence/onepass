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
                    serviceIdentifier: service, user: shownUser(identity), recordIdentifier: identity.recordId)
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

    /// The line the system shows for a password identity: the user (or, from the core, the title
    /// of a Login without one), or "Se connecte avec Apple" for a Login that signs in with a
    /// provider and has neither (spec 2026-11-03-ios-safari-autofill 5). Display only: the fill
    /// returns the Login's real fields.
    public static func shownUser(_ identity: FfiAutofillIdentity) -> String {
        guard !identity.signInWith.isEmpty else { return identity.user }
        return String(
            localized: "autofill.signsInWith \(providerName(identity.signInWith))", bundle: VaultKitStrings.bundle)
    }

    /// "Google", "GitHub", "Microsoft Entra ID", or the domain of a custom OIDC or SAML provider
    /// (the core spells them `google`, `entra_id`, `oidc:<domain>`).
    public static func providerName(_ raw: String) -> String {
        let known: [String: String] = [
            "google": "Google", "apple": "Apple", "microsoft": "Microsoft", "github": "GitHub",
            "facebook": "Facebook", "x": "X", "linkedin": "LinkedIn", "discord": "Discord", "slack": "Slack",
            "okta": "Okta", "entra_id": "Microsoft Entra ID",
        ]
        if let name = known[raw] { return name }
        if let colon = raw.firstIndex(of: ":") { return String(raw[raw.index(after: colon)...]) }
        return raw
    }
}
