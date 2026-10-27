import Foundation
import OnePassCore

/// Import of other password managers' exports. Detection and preview need no session (they only
/// parse and count); the import itself writes into one vault of the unlocked session.
///
/// Every core call runs on `CoreThread`, never on the main actor. The summaries hold counts and
/// static warning codes, never a value of the file. The caller owns the file bytes and wipes them
/// (`wipeImportBuffer`) once done; copies made by the bindings are wiped by the core.
extension VaultSession {
    /// Largest export the core reads (256 MiB).
    nonisolated public static let importMaxBytes = 256 << 20

    /// Format names the import takes (the OnePass archive is not one of them).
    nonisolated public static var importFormatNames: [String] { OnePassCore.importFormats() }

    /// The format of an export guessed from its content, `nil` when unknown. The file name is only a
    /// hint the core does not trust.
    nonisolated public static func detectImportFormat(fileName: String, data: Data) async -> String? {
        try? await CoreThread.run { OnePassCore.detectImportFormat(fileName: fileName, bytes: data) }
    }

    /// Parses the export and counts what it holds. Writes nothing. An encrypted or damaged export
    /// throws a `VaultError` whose message says what to do.
    nonisolated public static func previewImport(format: String, data: Data) async throws -> FfiImportSummary {
        do {
            return try await CoreThread.run { try OnePassCore.previewImport(format: format, bytes: data) }
        } catch {
            throw VaultError(error)
        }
    }

    /// Imports the export into `vaultID`: every item gets a new id (nothing is overwritten), the
    /// source folder becomes a tag, and nothing is written when one item does not validate. Reloads
    /// the lists and tells the sync layer, like any write.
    public func importItems(format: String, data: Data, vaultID: String) async throws -> FfiImportSummary {
        try await write { try $0.importItems(format: format, bytes: data, vaultId: vaultID) }
    }

    /// Overwrites the bytes of an export buffer once it is no longer needed.
    /// In place when it is the only reference; copies made by the bindings are out of reach (R5).
    nonisolated public static func wipeImportBuffer(_ data: inout Data) {
        data.withUnsafeMutableBytes { SecretBytes.zero($0) }
    }
}
