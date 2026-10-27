import Foundation
import Testing

@testable import VaultKit

@MainActor
struct ImportSessionTests {
    /// Messages are compared in French, the source language, whatever the machine's language.
    init() { VaultKitStrings.pinSourceLanguage() }

    static let chrome = Data("""
        name,url,username,password
        Exemple Atlas,https://atlas.exemple.fr,camille,motdepasse-fictif-1
        Exemple Borée,https://boree.exemple.fr,camille,motdepasse-fictif-2

        """.utf8)

    @Test func detectPreviewThenImportAddsItems() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let vault = session.allVaults[0].id

        let format = await VaultSession.detectImportFormat(fileName: "Chrome Passwords.csv", data: Self.chrome)
        #expect(format == "chrome-csv")
        let preview = try await VaultSession.previewImport(format: "chrome-csv", data: Self.chrome)
        #expect(preview.items == 2)
        #expect(preview.byType == [FfiImportTypeCount(itemType: .login, count: 2)])
        #expect(session.summaries.isEmpty, "a preview writes nothing")

        let done = try await session.importItems(format: "chrome-csv", data: Self.chrome, vaultID: vault)
        #expect(done.items == 2)
        #expect(session.summaries.count == 2, "the lists are reloaded after the import")
        #expect(Set(session.summaries.map(\.title)) == ["Exemple Atlas", "Exemple Borée"])
        #expect(session.summaries.allSatisfy { $0.vaultId == vault })
    }

    @Test func encryptedExportIsRefusedWithAMessage() async throws {
        let encrypted = Data(#"{"encrypted":true,"passwordProtected":true,"data":"2.x"}"#.utf8)
        #expect(await VaultSession.detectImportFormat(fileName: "bitwarden.json", data: encrypted) == "bitwarden-json")
        do {
            _ = try await VaultSession.previewImport(format: "bitwarden-json", data: encrypted)
            Issue.record("an encrypted export must be refused")
        } catch let error as VaultError {
            #expect(error.localizedMessage.contains("chiffré"))
        }
    }

    @Test func unknownFileIsNotDetectedAndBufferIsWiped() async {
        var data = Data("rien à voir".utf8)
        #expect(await VaultSession.detectImportFormat(fileName: "notes.txt", data: data) == nil)
        VaultSession.wipeImportBuffer(&data)
        #expect(data.allSatisfy { $0 == 0 })
    }

    @Test func importNeedsAnUnlockedSession() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        await #expect(throws: VaultError.passwordRequired) {
            _ = try await session.importItems(format: "chrome-csv", data: Self.chrome, vaultID: "x")
        }
    }
}
