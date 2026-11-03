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

/// The Emergency Kit: a one page A4 PDF opening with the warning that the kit plus the master
/// password give full access, then the Secret Key in clear, a QR code of it, the account
/// identifier and instructions in French (print it, keep the sheet offline, never photograph it
/// or store it in the cloud). Built on device with CoreGraphics,
/// CoreText and CoreImage only (no UIKit or AppKit), so it works on iOS and macOS. Nothing
/// is written to disk here: the caller owns the bytes.
public enum EmergencyKit {
    static let payloadPrefix = "onepass-kit:1:"
    /// Kits made since multi-account: `onepass-kit:2:<account id>:<Secret Key without dashes>`.
    static let payloadPrefixV2 = "onepass-kit:2:"

    /// What a scanned kit gives: its Secret Key (display format) and, on a version 2 kit, the account
    /// id that names its iCloud zone (multi-account ruling P8).
    public struct Scan: Equatable, Sendable {
        public let secretKey: String
        public let accountID: String?
        /// The server of a self-hosted account (spec D.4), nil otherwise.
        public var server: URL? = nil
    }

    // MARK: QR code

    /// Separates the kit body from the server URL of a self-hosted account in the payload.
    static let serverSeparator: Character = ";"

    /// The text encoded in the QR code: `onepass-kit:1:<Secret Key without dashes>`, then
    /// `;<server URL>` for an account on a server other than the OnePass one (spec D.4).
    public static func qrPayload(secretKey: String, server: URL? = nil) -> String {
        let bare = secretKey.filter { $0 != "-" && !$0.isWhitespace }.uppercased()
        return withServer(payloadPrefix + bare, server)
    }

    /// The version 2 payload: the account id, then the Secret Key without dashes, then the server
    /// of a self-hosted account.
    public static func qrPayload(secretKey: String, accountID: String, server: URL? = nil) -> String {
        let bare = secretKey.filter { $0 != "-" && !$0.isWhitespace }.uppercased()
        return withServer(payloadPrefixV2 + accountID.lowercased() + ":" + bare, server)
    }

    private static func withServer(_ body: String, _ server: URL?) -> String {
        guard let server else { return body }
        return body + String(serverSeparator) + server.absoluteString
    }

    /// The Secret Key (display format) carried by a scanned payload, or nil when the text is
    /// not a OnePass kit payload or the key is malformed.
    public static func parsePayload(_ s: String) -> String? {
        parseKit(s)?.secretKey
    }

    /// The Secret Key, the account id of a version 2 kit and the server of a self-hosted account
    /// of a scanned payload. Nil when the text is not a OnePass kit payload, the key is malformed
    /// or the account id is not 32 hex characters. A server URL that is not a valid one for this
    /// build is dropped (the key still counts).
    public static func parseKit(_ s: String) -> Scan? {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        let halves = trimmed.split(separator: serverSeparator, maxSplits: 1, omittingEmptySubsequences: false)
        let kit = String(halves.first ?? "")
        let server = halves.count > 1 ? URL(string: String(halves[1])) : nil
        let valid = server.flatMap { MailboxEndpoints.validate($0, allowHTTP: MailboxEndpoints.allowsLocalHTTP) ? $0 : nil }
        let lowered = kit.lowercased()
        if lowered.hasPrefix(payloadPrefix) {
            let body = String(kit.dropFirst(payloadPrefix.count))
            guard !body.isEmpty, let key = try? normalizeSecretKey(text: body) else { return nil }
            return Scan(secretKey: key, accountID: nil, server: valid)
        }
        guard lowered.hasPrefix(payloadPrefixV2) else { return nil }
        let parts = kit.dropFirst(payloadPrefixV2.count).split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2, let id = SignInZone.accountID(String(parts[0])), !parts[1].isEmpty,
            let key = try? normalizeSecretKey(text: String(parts[1]))
        else { return nil }
        return Scan(secretKey: key, accountID: id, server: valid)
    }

    /// A square QR code (error correction M, 4 module quiet zone, nearest neighbor scaling so
    /// modules stay sharp). The side is the largest whole multiple of the module count that
    /// fits `size`. Nil when the key is invalid.
    public static func qrImage(
        for secretKey: String, accountID: String? = nil, size: CGFloat, server: URL? = nil
    ) -> CGImage? {
        guard let display = try? normalizeSecretKey(text: secretKey) else { return nil }
        let filter = CIFilter.qrCodeGenerator()
        let payload = accountID.flatMap(SignInZone.accountID).map {
            qrPayload(secretKey: display, accountID: $0, server: server)
        }
        filter.message = Data((payload ?? qrPayload(secretKey: display, server: server)).utf8)
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

    /// The one page PDF. Throws `invalidSecretKey` when the key does not parse. `server`: the
    /// sync server of an account that is not on the OnePass server (a line and the QR carry it);
    /// nil for the OnePass server and iCloud.
    public static func pdf(
        secretKey: String, accountID: String, displayName: String, createdAt: Date, server: URL? = nil
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
            displayName: displayName, createdAt: createdAt, server: server)
        context.endPDFPage()
        context.closePDF()
        return data as Data
    }

    private static func draw(
        in context: CGContext, secretKey: String, accountID: String,
        displayName: String, createdAt: Date, server: URL?
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
        let strong = CTFontCreateWithName("Helvetica-Bold" as CFString, 11, nil)
        let mono = CTFontCreateWithName("Courier-Bold" as CFString, 11, nil)

        y = text(String(localized: "Emergency Kit OnePass", bundle: VaultKitStrings.bundle), font: title, top: y) - 10
        y = text(
            String(
                localized: "emergencyKit.kitPlusMasterPassword",
                bundle: VaultKitStrings.bundle),
            font: strong, top: y) - 12
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: VaultKitStrings.bundle.preferredLocalizations.first ?? "fr")
        formatter.dateStyle = .long
        formatter.timeStyle = .none
        formatter.timeZone = TimeZone(identifier: "UTC")
        y = text(String(localized: "emergencyKit.account \(displayName)", bundle: VaultKitStrings.bundle), font: body, top: y) - 4
        y = text(String(localized: "emergencyKit.accountId \(accountID)", bundle: VaultKitStrings.bundle), font: body, top: y) - 4
        y = text(String(localized: "emergencyKit.created \(formatter.string(from: createdAt))", bundle: VaultKitStrings.bundle), font: body, top: y) - 4
        if let server {
            y = text(String(localized: "kit.server \(server.absoluteString)", bundle: VaultKitStrings.bundle), font: body, top: y) - 4
        }
        y -= 20

        y = text(String(localized: "emergencyKit.secretKey", bundle: VaultKitStrings.bundle), font: heading, top: y) - 8
        y = text(
            String(localized: "emergencyKit.keyWorksWithMaster", bundle: VaultKitStrings.bundle),
            font: body, top: y) - 10
        y = text(secretKey, font: mono, top: y) - 16

        let qrSide: CGFloat = 150
        if let qr = qrImage(for: secretKey, accountID: accountID, size: qrSide, server: server) {
            let rect = CGRect(x: margin, y: y - qrSide, width: qrSide, height: qrSide)
            context.saveGState()
            context.interpolationQuality = .none
            context.draw(qr, in: rect)
            context.restoreGState()
        }
        let side = margin + qrSide + 20
        _ = text(
            String(localized: "emergencyKit.scanQrCodeWith", bundle: VaultKitStrings.bundle),
            font: body, top: y - 6, left: side, width: pageWidth - margin - side)
        y -= qrSide + 30

        y = text(String(localized: "emergencyKit.masterPassword", bundle: VaultKitStrings.bundle), font: heading, top: y) - 8
        y = text(
            String(
                localized: "emergencyKit.itNotPrintedOn",
                bundle: VaultKitStrings.bundle),
            font: body, top: y) - 30
        context.setStrokeColor(CGColor(gray: 0, alpha: 1))
        context.setLineWidth(0.8)
        context.move(to: CGPoint(x: margin, y: y))
        context.addLine(to: CGPoint(x: pageWidth - margin, y: y))
        context.strokePath()
        y -= 30

        y = text(String(localized: "emergencyKit.ifLoseThem", bundle: VaultKitStrings.bundle), font: heading, top: y) - 8
        let lines = [
            String(localized: "emergencyKit.withoutMasterPasswordAnd", bundle: VaultKitStrings.bundle),
            String(localized: "emergencyKit.printKitAndKeep", bundle: VaultKitStrings.bundle),
            String(localized: "emergencyKit.toAddNewDevice", bundle: VaultKitStrings.bundle),
            String(localized: "emergencyKit.ifThinkSomeoneElse", bundle: VaultKitStrings.bundle),
        ]
        for line in lines {
            y = text(line, font: body, top: y) - 8
        }
    }
}
