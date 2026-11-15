import Foundation

/// An organisation invitation link (`onepass://org/join?...`, R4), told apart from the other
/// `onepass://` links before any parsing: its secrets are read by the core only (`orgInviteParse`),
/// once the vault is open.
public enum OrgInviteLink {
    public static func isJoinLink(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "onepass", url.host()?.lowercased() == "org" else { return false }
        return url.path() == "/join" || url.path() == "/join/"
    }
}

extension OrgPinRefusal {
    /// What a refused pin plan tells the user, before any slot exists: each refusal with what to do.
    public var message: String {
        let key: String.LocalizationValue =
            switch self {
            case .mdmInvalid: "org.refusal.mdmInvalid"
            case .mdmMismatch: "org.refusal.mdmMismatch"
            case .dnsMismatch: "org.refusal.dnsMismatch"
            }
        return String(localized: key, bundle: VaultKitStrings.bundle)
    }
}
