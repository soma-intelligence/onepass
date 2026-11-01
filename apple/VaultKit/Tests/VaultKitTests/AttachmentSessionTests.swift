import Foundation
import Testing

@testable import VaultKit

@MainActor
struct AttachmentSessionTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    @Test func attachReadAndRemoveAPDF() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let item = try await addItem(session, title: "Exemple Atlas", type: .login)
        let pdf = Data("%PDF-1.7 contrat fictif".utf8)

        let with = try await session.addAttachment(
            itemID: item.id, vaultID: item.vaultId, name: "contrat.pdf", mime: "application/pdf", data: pdf)
        #expect(with.attachments.map(\.name) == ["contrat.pdf"])
        let attachment = try #require(with.attachments.first)
        #expect(attachment.size == UInt64(pdf.count))

        let read = try await session.attachmentData(
            itemID: item.id, vaultID: item.vaultId, attachmentID: attachment.id)
        #expect(read == pdf)

        let without = try await session.removeAttachment(
            itemID: item.id, vaultID: item.vaultId, attachmentID: attachment.id)
        #expect(without.attachments.isEmpty)
        await #expect(throws: VaultError.notFound) {
            _ = try await session.attachmentData(itemID: item.id, vaultID: item.vaultId, attachmentID: attachment.id)
        }
    }

    @Test func attachmentChunksAreAcceptedFromTheServer() {
        let id = String(repeating: "ab", count: 16)
        let chunk = RemoteRecord(name: RecordName(kind: 25, id: id), version: 1, data: Data([1]), serverMeta: nil)
        #expect(SyncCoordinator.isValid(chunk))
        let unknown = RemoteRecord(name: RecordName(kind: 26, id: id), version: 1, data: Data([1]), serverMeta: nil)
        #expect(!SyncCoordinator.isValid(unknown))
    }
}
