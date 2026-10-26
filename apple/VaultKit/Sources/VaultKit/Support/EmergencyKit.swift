import CoreGraphics
import CoreImage
import CoreImage.CIFilterBuiltins
import CoreText
import Foundation
import OnePassCore

/// Errors from `EmergencyKit`. They never carry the Secret Key.
public enum EmergencyKitError: Error, Equatable {
    /// The text is not a valid Secret Key.
    case invalidSecretKey
    /// The PDF could not be produced.
    case renderFailed
}

/// The Emergency Kit: a one page A4 PDF with the Secret Key in clear, a QR code of it, the
/// account identifier and instructions in French. Built on device with CoreGraphics,
/// CoreText and CoreImage only (no UIKit or AppKit), so it works on iOS and macOS. Nothing
/// is written to disk here: the caller owns the bytes.
public enum EmergencyKit {
    static let payloadPrefix = "onepass-kit:1:"

    // MARK: QR code

    /// The text encoded in the QR code: `onepass-kit:1:<Secret Key without dashes>`.
    public static func qrPayload(secretKey: String) -> String {
        let bare = secretKey.filter { $0 != "-" && !$0.isWhitespace }.uppercased()
        return payloadPrefix + bare
    }

    /// The Secret Key (display format) carried by a scanned payload, or nil when the text is
    /// not a version 1 OnePass kit payload or the key is malformed.
    public static func parsePayload(_ s: String) -> String? {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix(payloadPrefix) else { return nil }
        let body = String(trimmed.dropFirst(payloadPrefix.count))
        guard !body.isEmpty else { return nil }
        return try? normalizeSecretKey(text: body)
    }

    /// A square QR code (error correction M, 4 module quiet zone, nearest neighbor scaling so
    /// modules stay sharp). The side is the largest whole multiple of the module count that
    /// fits `size`. Nil when the key is invalid.
    public static func qrImage(for secretKey: String, size: CGFloat) -> CGImage? {
        guard let display = try? normalizeSecretKey(text: secretKey) else { return nil }
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(qrPayload(secretKey: display).utf8)
        filter.correctionLevel = "M"
        guard let raw = filter.outputImage else { return nil }
        let quiet: CGFloat = 4
        let modules = raw.extent.width
        let scale = max(1, floor(size / (modules + 2 * quiet)))
        let side = (modules + 2 * quiet) * scale
        let code = raw
            .samplingNearest()
            .transformed(by: CGAffineTransform(scaleX: scale, y: scale))
            .transformed(by: CGAffineTransform(translationX: quiet * scale, y: quiet * scale))
        let white = CIImage(color: .white).cropped(to: CGRect(x: 0, y: 0, width: side, height: side))
        let composed = code.composited(over: white).cropped(to: white.extent)
        return CIContext(options: [.useSoftwareRenderer: true])
            .createCGImage(composed, from: composed.extent)
    }

    // MARK: PDF

    private static let pageWidth: CGFloat = 595
    private static let pageHeight: CGFloat = 842
    private static let margin: CGFloat = 50

    /// The one page PDF. Throws `invalidSecretKey` when the key does not parse.
    public static func pdf(
        secretKey: String, accountID: String, displayName: String, createdAt: Date
    ) throws -> Data {
        guard let key = try? normalizeSecretKey(text: secretKey) else {
            throw EmergencyKitError.invalidSecretKey
        }
        let data = NSMutableData()
        guard let consumer = CGDataConsumer(data: data) else { throw EmergencyKitError.renderFailed }
        var mediaBox = CGRect(x: 0, y: 0, width: pageWidth, height: pageHeight)
        let info: [CFString: Any] = [
            kCGPDFContextTitle: "Emergency Kit OnePass",
            kCGPDFContextCreator: "OnePass",
        ]
        guard let context = CGContext(consumer: consumer, mediaBox: &mediaBox, info as CFDictionary) else {
            throw EmergencyKitError.renderFailed
        }
        context.beginPDFPage(nil)
        draw(
            in: context, secretKey: key, accountID: accountID,
            displayName: displayName, createdAt: createdAt)
        context.endPDFPage()
        context.closePDF()
        return data as Data
    }

    private static func draw(
        in context: CGContext, secretKey: String, accountID: String,
        displayName: String, createdAt: Date
    ) {
        let contentWidth = pageWidth - 2 * margin
        var y = pageHeight - margin

        func text(
            _ string: String, font: CTFont, top: CGFloat, left: CGFloat = margin,
            width: CGFloat = contentWidth, gray: CGFloat = 0
        ) -> CGFloat {
            let attributes: [CFString: Any] = [
                kCTFontAttributeName: font,
                kCTForegroundColorAttributeName: CGColor(gray: gray, alpha: 1),
            ]
            let attributed = CFAttributedStringCreate(nil, string as CFString, attributes as CFDictionary)!
            let framesetter = CTFramesetterCreateWithAttributedString(attributed)
            let fit = CTFramesetterSuggestFrameSizeWithConstraints(
                framesetter, CFRange(location: 0, length: 0),
                nil, CGSize(width: width, height: .greatestFiniteMagnitude), nil)
            let rect = CGRect(x: left, y: top - ceil(fit.height), width: width, height: ceil(fit.height))
            let frame = CTFramesetterCreateFrame(
                framesetter, CFRange(location: 0, length: 0), CGPath(rect: rect, transform: nil), nil)
            CTFrameDraw(frame, context)
            return rect.minY
        }

        let title = CTFontCreateWithName("Helvetica-Bold" as CFString, 24, nil)
        let heading = CTFontCreateWithName("Helvetica-Bold" as CFString, 14, nil)
        let body = CTFontCreateWithName("Helvetica" as CFString, 11, nil)
        let mono = CTFontCreateWithName("Courier-Bold" as CFString, 11, nil)

        y = text("Emergency Kit OnePass", font: title, top: y) - 10
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "fr_FR")
        formatter.dateStyle = .long
        formatter.timeStyle = .none
        formatter.timeZone = TimeZone(identifier: "UTC")
        y = text("Compte : \(displayName)", font: body, top: y) - 4
        y = text("Identifiant du compte : \(accountID)", font: body, top: y) - 4
        y = text("Créé le \(formatter.string(from: createdAt))", font: body, top: y) - 24

        y = text("Ta Secret Key", font: heading, top: y) - 8
        y = text(
            "Cette clé s'ajoute à ton mot de passe maître pour protéger ton coffre. "
                + "Elle est stockée sur tes appareils et n'est jamais envoyée à personne.",
            font: body, top: y) - 10
        y = text(secretKey, font: mono, top: y) - 16

        let qrSide: CGFloat = 150
        if let qr = qrImage(for: secretKey, size: qrSide) {
            let rect = CGRect(x: margin, y: y - qrSide, width: qrSide, height: qrSide)
            context.saveGState()
            context.interpolationQuality = .none
            context.draw(qr, in: rect)
            context.restoreGState()
        }
        let side = margin + qrSide + 20
        _ = text(
            "Scanne ce QR code avec OnePass sur ton iPhone ou ton iPad pour ajouter un "
                + "appareil. Sur un Mac, tape la Secret Key à la main.",
            font: body, top: y - 6, left: side, width: pageWidth - margin - side)
        y -= qrSide + 30

        y = text("Ton mot de passe maître", font: heading, top: y) - 8
        y = text(
            "Ne l'imprime pas. Si tu veux le garder sur papier, écris-le à la main sur la ligne ci-dessous.",
            font: body, top: y) - 30
        context.setStrokeColor(CGColor(gray: 0, alpha: 1))
        context.setLineWidth(0.8)
        context.move(to: CGPoint(x: margin, y: y))
        context.addLine(to: CGPoint(x: pageWidth - margin, y: y))
        context.strokePath()
        y -= 30

        y = text("En cas de perte", font: heading, top: y) - 8
        let lines = [
            "Sans ton mot de passe maître et ta Secret Key, personne ne peut ouvrir ton coffre, "
                + "pas même nous. Il n'existe aucun moyen de les récupérer.",
            "Range cette page hors ligne, dans un endroit sûr (coffre, tiroir fermé à clé).",
            "Pour ajouter un nouvel appareil, ouvre OnePass, choisis « J'ai mon Emergency Kit », "
                + "puis saisis ou scanne la Secret Key et entre ton mot de passe maître.",
            "Si tu penses que cette page a été vue par quelqu'un d'autre, crée un nouveau compte "
                + "et déplace tes données.",
        ]
        for line in lines {
            y = text(line, font: body, top: y) - 8
        }
    }
}
