import Foundation

/// Whether a managed account can live on its organisation's server in this build.
public enum OrgServers {
    /// A managed kind whose server URL passes `MailboxEndpoints.validate` and whose org id is 32 hex
    /// characters. Personal and business kinds are not org servers.
    public static func isUsable(_ kind: FfiAccountKind, allowHTTP: Bool = MailboxEndpoints.allowsLocalHTTP) -> Bool {
        guard case .managed(let serverURL, let orgID) = kind, isOrgID(orgID),
            let url = URL(string: serverURL)
        else { return false }
        return MailboxEndpoints.validate(url, allowHTTP: allowHTTP)
    }

    /// 32 hex characters (16 bytes), as the core writes org and mailbox ids.
    static func isOrgID(_ text: String) -> Bool {
        text.utf8.count == 32
            && text.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) || (0x41...0x46).contains($0) }
    }
}
