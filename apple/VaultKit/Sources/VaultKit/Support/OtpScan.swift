import Foundation
import UniformTypeIdentifiers

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

extension OtpScan {
    /// The image of a drop: its image data, or the file a Finder drag points to.
    @MainActor public static func imageData(from provider: NSItemProvider) async -> Data? {
        if provider.hasItemConformingToTypeIdentifier(UTType.image.identifier),
            let data = await load(provider, type: .image)
        {
            return data
        }
        guard provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier),
            let reference = await load(provider, type: .fileURL),
            let url = URL(dataRepresentation: reference, relativeTo: nil), url.isFileURL
        else { return nil }
        return try? Data(contentsOf: url)
    }

    @MainActor private static func load(_ provider: NSItemProvider, type: UTType) async -> Data? {
        await withCheckedContinuation { continuation in
            _ = provider.loadDataRepresentation(for: type) { data, _ in continuation.resume(returning: data) }
        }
    }
}
