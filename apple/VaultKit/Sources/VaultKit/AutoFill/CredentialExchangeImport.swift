#if !os(watchOS)
import AuthenticationServices
import Foundation

/// Credentials another app hands over through the system's Credential Exchange (iOS, macOS and
/// visionOS 26: Passwords > Export Data to Another App > OnePass). The system opens OnePass with a
/// `ASCredentialExchangeActivity` user activity carrying a one-time token; `receive(token:)` reads
/// the credentials with it, and `cxfJSON` turns them into the FIDO CXF JSON the core's `cxf` import
/// already reads (passkeys with their private key, passwords, codes, cards, Wi-Fi, notes). The
/// bytes then follow the Import sheet: preview, vault choice, import, buffer wiped.
///
/// `ASExportedCredentialData` encodes the CXF member names itself. Only its dates differ: Foundation
/// writes seconds since 2001, CXF wants Unix seconds, written here as whole numbers.
public enum CredentialExchangeImport {
    /// The core import format these bytes are read as.
    public static let format = "cxf"

    /// The token of a Credential Exchange user activity, or nil for any other activity.
    public static func token(of activity: NSUserActivity) -> UUID? {
        guard activity.activityType == ASCredentialExchangeActivity else { return nil }
        return activity.userInfo?[ASCredentialImportToken] as? UUID
    }

    /// The exported credentials, as CXF JSON. Holds secrets: the caller wipes the bytes once they
    /// are imported (`VaultSession.wipeImportBuffer`).
    public static func receive(token: UUID) async throws -> Data {
        let exported = try await ASCredentialImportManager().importCredentials(token: token)
        return try cxfJSON(exported)
    }

    public static func cxfJSON(_ exported: ASExportedCredentialData) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(Int64(date.timeIntervalSince1970.rounded(.down)))
        }
        return try encoder.encode(exported)
    }
}
#endif
