import Foundation
import Testing

@testable import VaultKit

@MainActor
@Suite("Backup restore and plaintext export", .serialized)
struct ArchiveTests {
    static let passphrase = "orbite-velours-cascade-lanterne-92"

    private func unlockedSession(_ h: SessionHarness) async throws -> VaultSession {
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        return session
    }

    private func addLogin(_ session: VaultSession, title: String) async throws -> FfiItem {
        var item = try session.newItem(type: .login, vaultID: session.allVaults[0].id)
        item.title = title
        fillRequired(&item)
        return try await session.save(item)
    }

    private func backup(_ session: VaultSession) async throws -> Data {
        let password = SecretBytes(utf8: testPassword)
        let phrase = SecretBytes(utf8: Self.passphrase)
        defer { password.wipe(); phrase.wipe() }
        return try await session.exportEncryptedBackup(password: password, passphrase: phrase)
    }

    @Test func ownBackupRestoresByTheAccountWithAVerifiedSignature() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlockedSession(h)
        let item = try await addLogin(session, title: "Atlas")
        let archive = try await backup(session)
        try await session.deletePermanently(itemID: item.id, vaultID: item.vaultId)
        #expect(session.summaries.isEmpty)

        let info = try await session.archiveInfo(archive)
        #expect(info.forThisAccount && info.kind == .backup && info.signed)
        let preview = try await session.previewRestore(archive, passphrase: nil)
        #expect(preview.signatureVerified && preview.items == 1 && preview.skipped == 0)
        #expect(session.summaries.isEmpty)

        let done = try await session.restoreArchive(archive, passphrase: nil)
        #expect(done.items == 1 && done.epoch != nil)
        #expect(session.summaries.map(\.title) == ["Atlas"])
        #expect(session.state == .unlocked)
    }

    @Test func tamperedBackupIsRefusedWithoutLockingTheVault() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlockedSession(h)
        _ = try await addLogin(session, title: "Atlas")
        var archive = try await backup(session)
        archive[archive.count - 1] ^= 1
        await #expect(throws: ArchiveError.tampered) {
            _ = try await session.previewRestore(archive, passphrase: nil)
        }
        // An archive error is about the file, not the store: the vault stays open.
        #expect(session.state == .unlocked)
        #expect(session.summaries.map(\.title) == ["Atlas"])
    }

    @Test func foreignBackupAsksItsPassphrase() async throws {
        let source = try SessionHarness()
        defer { source.cleanUp() }
        let a = try await unlockedSession(source)
        _ = try await addLogin(a, title: "Atlas")
        let archive = try await backup(a)

        let target = try SessionHarness()
        defer { target.cleanUp() }
        let b = try await unlockedSession(target)
        let info = try await b.archiveInfo(archive)
        #expect(!info.forThisAccount && info.hasPassphrase)
        await #expect(throws: ArchiveError.passphraseRequired) {
            _ = try await b.previewRestore(archive, passphrase: nil)
        }
        let wrong = SecretBytes(utf8: "mauvaise-phrase-de-passe")
        await #expect(throws: ArchiveError.wrongPassphrase) {
            _ = try await b.previewRestore(archive, passphrase: wrong)
        }
        let phrase = SecretBytes(utf8: Self.passphrase)
        let done = try await b.restoreArchive(archive, passphrase: phrase)
        #expect(!done.signatureVerified && done.items == 1 && done.vaultsCreated == 1)
        #expect(b.summaries.map(\.title) == ["Atlas"])
    }

    @Test func notAnArchive() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlockedSession(h)
        await #expect(throws: ArchiveError.notAnArchive) {
            _ = try await session.archiveInfo(Data("title,url\n".utf8))
        }
    }

    @Test func plaintextCSVAsksTheMasterPassword() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlockedSession(h)
        _ = try await addLogin(session, title: "Atlas")
        let wrong = SecretBytes(utf8: "pas le bon")
        await #expect(throws: VaultError.wrongPassword) {
            _ = try await session.exportPlaintextCSV(password: wrong, vaultIDs: [])
        }
        let password = SecretBytes(utf8: testPassword)
        let csv = try await session.exportPlaintextCSV(password: password, vaultIDs: [])
        let text = String(decoding: csv, as: UTF8.self)
        #expect(text.hasPrefix("title,type,vault,url,username,password,otpauth,notes,tags,extra"))
        #expect(text.contains("Atlas"))
    }

    @Test(arguments: [
        (OnePassError.Integrity(kind: "signature"), ArchiveError.tampered),
        (OnePassError.Integrity(kind: "aead"), ArchiveError.tampered),
        (OnePassError.WrongPassword, ArchiveError.wrongPassphrase),
        (OnePassError.InvalidInput(what: "archive passphrase"), ArchiveError.passphraseRequired),
        (OnePassError.InvalidInput(what: "archive of another account"), ArchiveError.otherAccount),
        (OnePassError.InvalidInput(what: "archive from a newer version"), ArchiveError.newerVersion),
        (OnePassError.InvalidInput(what: "archive magic"), ArchiveError.notAnArchive),
    ])
    func coreErrorsMapToArchiveErrors(core: OnePassError, expected: ArchiveError) {
        #expect(ArchiveError(core) == expected)
        #expect(!expected.message.isEmpty)
    }
}

@Suite("Plaintext export file")
struct PlaintextExportFileTests {
    @Test func fileNameSaysUnencrypted() {
        let date = Date(timeIntervalSince1970: 1_793_000_000)  // 2026-10-26 in UTC
        let utc = TimeZone(identifier: "UTC")!
        #expect(PlaintextExportFile.fileName(for: date, timeZone: utc) == "OnePass export non chiffré 2026-10-26.csv")
    }

    @Test func writesOwnerOnlyAndNeverOverwrites() throws {
        let parent = FileManager.default.temporaryDirectory
            .appendingPathComponent("onepass-csv-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parent) }
        let target = parent.appendingPathComponent("export.csv")
        try PlaintextExportFile.writeNew(Data("a,b\n".utf8), to: target)
        let mode = try FileManager.default.attributesOfItem(atPath: target.path)[.posixPermissions] as? Int
        #expect(mode == 0o600)
        #expect(throws: (any Error).self) {
            try PlaintextExportFile.writeNew(Data("c".utf8), to: target)
        }
        #expect(try Data(contentsOf: target) == Data("a,b\n".utf8))

        let shared = try PlaintextExportFile.writeTemporary(Data("x".utf8), named: "e.csv", under: parent)
        #expect(shared.deletingLastPathComponent().lastPathComponent.hasPrefix("plaintext-"))
        PlaintextExportFile.remove(shared, under: parent)
        #expect(!FileManager.default.fileExists(atPath: shared.path))
        let kept = try PlaintextExportFile.writeTemporary(Data("y".utf8), named: "f.csv", under: parent)
        PlaintextExportFile.sweep(in: parent)
        #expect(!FileManager.default.fileExists(atPath: kept.path))
        #expect(FileManager.default.fileExists(atPath: target.path))
    }
}
