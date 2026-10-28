#if canImport(PDFKit)
import Foundation
import PDFKit

/// Why the text of a PDF could not be read for the `pdf-text` import.
public enum PDFImportError: Error, Equatable, Sendable {
    /// Not a PDF, or a damaged one.
    case unreadable
    /// Protected by a password: it has to be opened and saved without one first.
    case locked
    /// No text layer (a scan or a photo): there is nothing to read.
    case noText
}

/// The `pdf-text` import: a printed password list or a 1Password Emergency Kit. PDFKit reads the
/// text on this device; the core parses that text into Logins (`pdf_text` in the Rust core) and the
/// usual preview counts them before anything is written.
extension VaultSession {
    /// The UTF-8 text of the PDF in `data`, pages separated by form feeds, for `previewImport` and
    /// `importItems` with the `pdf-text` format. A filled form field whose name says "password"
    /// (the box of an Emergency Kit) is added as a `Password:` line.
    ///
    /// The strings PDFKit makes cannot be wiped; the returned bytes can, with `wipeImportBuffer`.
    nonisolated public static func pdfImportText(_ data: Data) throws(PDFImportError) -> Data {
        guard let document = PDFDocument(data: data) else { throw .unreadable }
        if document.isLocked, !document.unlock(withPassword: "") { throw .locked }
        var pages: [String] = []
        for index in 0..<document.pageCount {
            guard let page = document.page(at: index) else { continue }
            var lines = [page.string ?? ""]
            for annotation in page.annotations where annotation.widgetFieldType == .text {
                guard let value = annotation.widgetStringValue?.trimmingCharacters(in: .whitespacesAndNewlines),
                      !value.isEmpty,
                      annotation.fieldName?.localizedCaseInsensitiveContains("password") == true
                else { continue }
                lines.append("Password: \(value)")
            }
            pages.append(lines.joined(separator: "\n"))
        }
        let text = pages.joined(separator: "\u{0C}")
        guard text.contains(where: { !$0.isWhitespace }) else { throw .noText }
        return Data(text.utf8)
    }

    /// Whether `data` is a PDF file (its magic, as the core's detection reads it).
    nonisolated public static func isPDF(_ data: Data) -> Bool {
        data.starts(with: Array("%PDF-".utf8))
    }
}
#endif
