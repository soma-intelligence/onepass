import CoreGraphics
import CoreText
import Foundation
import Testing

@testable import VaultKit

@MainActor
struct PDFImportTests {
    /// A one-page PDF with a real text layer, one string per line. `password` encrypts it.
    static func pdf(_ lines: [String], password: String? = nil) -> Data {
        let data = NSMutableData()
        var box = CGRect(x: 0, y: 0, width: 595, height: 842)
        var info: [CFString: Any] = [:]
        if let password {
            info[kCGPDFContextUserPassword] = password
            info[kCGPDFContextOwnerPassword] = password
        }
        let consumer = CGDataConsumer(data: data as CFMutableData)!
        let context = CGContext(consumer: consumer, mediaBox: &box, info as CFDictionary)!
        context.beginPDFPage(nil)
        let font = CTFontCreateWithName("Helvetica" as CFString, 12, nil)
        for (index, line) in lines.enumerated() {
            let text = NSAttributedString(
                string: line, attributes: [NSAttributedString.Key(kCTFontAttributeName as String): font])
            context.textPosition = CGPoint(x: 40, y: 800 - CGFloat(index) * 18)
            CTLineDraw(CTLineCreateWithAttributedString(text), context)
        }
        context.endPDFPage()
        context.closePDF()
        return data as Data
    }

    static let list = pdf([
        "Mots de passe (valeurs fictives)",
        "Exemple Atlas",
        "Site web : atlas.exemple.fr",
        "Identifiant : camille",
        "Mot de passe : motdepasse-fictif-1",
        "Exemple Borée",
        "Site web : https://boree.exemple.fr",
        "Identifiant : camille",
        "Mot de passe : motdepasse-fictif-2",
    ])

    @Test func printedListPreviewsThenImportsLogins() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let vault = session.allVaults[0].id

        #expect(VaultSession.isPDF(Self.list))
        #expect(await VaultSession.detectImportFormat(fileName: "list.pdf", data: Self.list) == "pdf-text")
        var text = try VaultSession.pdfImportText(Self.list)
        #expect(!VaultSession.isPDF(text))
        let preview = try await VaultSession.previewImport(format: "pdf-text", data: text)
        #expect(preview.byType == [FfiImportTypeCount(itemType: .login, count: 2)])
        #expect(session.summaries.isEmpty, "a preview writes nothing")

        let done = try await session.importItems(format: "pdf-text", data: text, vaultID: vault)
        VaultSession.wipeImportBuffer(&text)
        #expect(done.items == 2)
        #expect(Set(session.summaries.map(\.title)) == ["Exemple Atlas", "Exemple Borée"])
    }

    @Test func rawPDFBytesAreRefusedByTheCore() async {
        await #expect(throws: VaultError.self) {
            _ = try await VaultSession.previewImport(format: "pdf-text", data: Self.list)
        }
    }

    @Test func unreadableBlankAndLockedPDFsSayWhy() {
        #expect(throws: PDFImportError.unreadable) { try VaultSession.pdfImportText(Data("pas un pdf".utf8)) }
        #expect(throws: PDFImportError.noText) { try VaultSession.pdfImportText(Self.pdf([])) }
        #expect(throws: PDFImportError.locked) {
            try VaultSession.pdfImportText(Self.pdf(["Mot de passe : x"], password: "fictif"))
        }
    }
}
