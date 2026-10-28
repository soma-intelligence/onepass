import Foundation
import OnePassCore

/// Why an archive did not open or restore. About the file, never the store: an archive refused for
/// its signature does not put the vault in "Données refusées".
public enum ArchiveError: Error, Equatable, Sendable {
    /// Signature missing or wrong, or a bit of the archive changed.
    case tampered
    case wrongPassphrase
    /// The archive is not for this account: its passphrase is needed.
    case passphraseRequired
    /// Another account's backup with no passphrase: it cannot open here.
    case otherAccount
    case newerVersion
    case notAnArchive
    case other(VaultError)

    public init(_ error: any Error) {
        switch error {
        case let error as ArchiveError:
            self = error
        case let error as OnePassError:
            switch error {
            case .Integrity: self = .tampered
            case .WrongPassword: self = .wrongPassphrase
            case .InvalidInput(let what):
                switch what {
                case "archive passphrase": self = .passphraseRequired
                case "archive of another account": self = .otherAccount
                case "archive from a newer version": self = .newerVersion
                case "passphrase": self = .wrongPassphrase
                default: self = what.hasPrefix("archive") ? .notAnArchive : .other(VaultError(error))
                }
            default: self = .other(VaultError(error))
            }
        default:
            self = .other(VaultError(error))
        }
    }

    public var message: String {
        switch self {
        case .tampered:
            String(localized: "Cette sauvegarde a été modifiée ou abîmée : sa signature ou son contenu ne correspond pas. Rien n'a été restauré.", bundle: VaultKitStrings.bundle)
        case .wrongPassphrase:
            String(localized: "Phrase de passe incorrecte.", bundle: VaultKitStrings.bundle)
        case .passphraseRequired:
            String(localized: "Cette sauvegarde vient d'un autre compte : saisis sa phrase de passe.", bundle: VaultKitStrings.bundle)
        case .otherAccount:
            String(localized: "Cette sauvegarde appartient à un autre compte et n'a pas de phrase de passe : elle ne s'ouvre qu'avec ce compte.", bundle: VaultKitStrings.bundle)
        case .newerVersion:
            String(localized: "Cette sauvegarde vient d'une version plus récente de OnePass. Mets l'app à jour, puis réessaie.", bundle: VaultKitStrings.bundle)
        case .notAnArchive:
            String(localized: "Ce fichier n'est pas une sauvegarde OnePass.", bundle: VaultKitStrings.bundle)
        case .other(let error):
            error.localizedMessage
        }
    }
}

/// Restore of a OnePass archive (`.onepass`) and its preview. The archive's header says how it
/// opens: by this account (its signature is then verified, no passphrase) or by its passphrase.
/// Nothing in the account is overwritten: items already there are skipped and counted. The caller
/// owns the archive bytes; the passphrase crosses the FFI as bytes, wiped by the core.
extension VaultSession {
    /// The archive's clear header and whether it is for this account. Opens nothing.
    public func archiveInfo(_ data: Data) async throws(ArchiveError) -> FfiArchiveInfo {
        try await onArchive(writes: false) { try $0.archiveInfo(bytes: data) }
    }

    /// Opens the archive and counts what a restore would write. Writes nothing.
    public func previewRestore(_ data: Data, passphrase: SecretBytes?) async throws(ArchiveError) -> FfiRestoreSummary {
        try await onArchive(writes: false) { session in
            try Self.withOptional(passphrase) { try session.previewRestore(bytes: data, passphrase: $0) }
        }
    }

    /// Restores the archive (missing vaults created, items absent from the account written with
    /// their id, a restore epoch issued), then reloads the lists and tells the sync layer.
    public func restoreArchive(_ data: Data, passphrase: SecretBytes?) async throws(ArchiveError) -> FfiRestoreSummary {
        try await onArchive(writes: true) { session in
            try Self.withOptional(passphrase) { try session.restoreArchive(bytes: data, passphrase: $0) }
        }
    }

    nonisolated static func withOptional<R>(_ secret: SecretBytes?, _ body: (Data?) throws -> R) rethrows -> R {
        guard let secret else { return try body(nil) }
        return try secret.withData { try body($0) }
    }
}

/// The plaintext CSV export file: owner-only, never over an existing file, and the temporary copy
/// behind the share sheet handled like the backup's (one `plaintext-<UUID>` folder, excluded from
/// backups, complete file protection, removed when the sheet closes, swept at launch).
public enum PlaintextExportFile {
    static let folderPrefix = "plaintext-"

    /// "OnePass export non chiffré 2026-10-26.csv" (the day in the device's time zone).
    public static func fileName(for date: Date, timeZone: TimeZone = .current) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let parts = calendar.dateComponents([.year, .month, .day], from: date)
        let day = String(format: "%04d-%02d-%02d", parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
        return "OnePass export non chiffré \(day).csv"
    }

    /// Creates `url` with mode 0600 and writes `data`; refuses an existing file (or link).
    public static func writeNew(_ data: Data, to url: URL) throws {
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteFileExists) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            try? FileManager.default.removeItem(at: url)
            throw error
        }
        #if os(iOS) || os(visionOS) || os(watchOS)
        try? FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
        #endif
    }

    /// Writes `data` to `<parent>/plaintext-<UUID>/<name>` for the share sheet and returns its URL.
    public static func writeTemporary(_ data: Data, named name: String, under parent: URL) throws -> URL {
        guard !name.isEmpty, !name.contains("/"), name != ".", name != ".." else {
            throw CocoaError(.fileWriteInvalidFileName)
        }
        let folder = parent.appendingPathComponent(folderPrefix + UUID().uuidString, isDirectory: true)
        do {
            try FileManager.default.createDirectory(
                at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var target = folder
            try target.setResourceValues(values)
            let url = folder.appendingPathComponent(name)
            try writeNew(data, to: url)
            return url
        } catch {
            try? FileManager.default.removeItem(at: folder)
            throw error
        }
    }

    /// Removes the folder holding `file`, only when `file` was written by `writeTemporary` under `parent`.
    public static func remove(_ file: URL, under parent: URL) {
        let folder = file.deletingLastPathComponent()
        guard folder.lastPathComponent.hasPrefix(folderPrefix),
            folder.deletingLastPathComponent().standardizedFileURL.resolvingSymlinksInPath().path
                == parent.standardizedFileURL.resolvingSymlinksInPath().path
        else { return }
        try? FileManager.default.removeItem(at: folder)
    }

    /// Removes every temporary folder left in `parent` by a previous run.
    public static func sweep(in parent: URL) {
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: parent.path)) ?? []
        for name in entries where name.hasPrefix(folderPrefix) {
            try? FileManager.default.removeItem(at: parent.appendingPathComponent(name, isDirectory: true))
        }
    }
}
