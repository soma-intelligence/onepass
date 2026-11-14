import Foundation

/// What a scanned QR code gives the one-time password row.
public enum OtpScanResult: Equatable, Sendable {
    /// The value to store in the field: one account's `otpauth://` link.
    case value(String)
    /// A Google Authenticator export of several accounts: "Ajouter un code" handles those.
    case severalAccounts(Int)
    /// Anything else.
    case notOtp
}

/// Reads a QR payload for the editor's one-time password row. Nothing leaves the device.
public enum OtpScan {
    public static func read(_ payload: String) -> OtpScanResult {
        let text = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        guard OtpLink.isLink(text), let accounts = try? OtpLink.accounts(in: text), !accounts.isEmpty else {
            return .notOtp
        }
        return accounts.count == 1 ? .value(accounts[0].uri) : .severalAccounts(accounts.count)
    }
}
