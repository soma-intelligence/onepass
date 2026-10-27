import CoreImage
import Foundation
import PDFKit
import Testing

@testable import VaultKit

@Suite("EmergencyKit")
struct EmergencyKitTests {
    /// Messages are compared in French, the source language, whatever the machine's language.
    init() { VaultKitStrings.pinSourceLanguage() }

    /// Fictional key: the core's published test vector.
    static let secretKey = "AAAQ-EAYE-AUDA-OCAJ-BIFQ-YDIO-B4IB-CEQT-CQKR-MFYY-DENB-WHA5-DYPQ-B"
    static let accountID = String(repeating: "0", count: 32)

    @Test func pdfContainsSecretKeyAndIsOnePage() throws {
        let data = try EmergencyKit.pdf(
            secretKey: Self.secretKey,
            accountID: Self.accountID,
            displayName: "Camille Durand",
            createdAt: Date(timeIntervalSince1970: 1_800_000_000)
        )
        let document = try #require(PDFDocument(data: data))
        #expect(document.pageCount == 1)
        let page = try #require(document.page(at: 0))
        let bounds = page.bounds(for: .mediaBox)
        #expect(bounds.width == 595)
        #expect(bounds.height == 842)
        let text = try #require(document.string)
        #expect(text.contains(Self.secretKey))
        #expect(text.contains("Emergency Kit OnePass"))
        #expect(text.contains("Ta Secret Key"))
        #expect(text.contains("Ton mot de passe maître"))
        #expect(text.contains("En cas de perte"))
        #expect(text.contains("Camille Durand"))
        #expect(text.contains(Self.accountID))
        #expect(!text.contains("\u{2014}"))
    }

    @Test func pdfRejectsInvalidSecretKey() {
        #expect(throws: (any Error).self) {
            try EmergencyKit.pdf(
                secretKey: "pas une cle", accountID: Self.accountID,
                displayName: "Camille Durand", createdAt: Date())
        }
    }

    @Test func qrPayloadRoundtrips() {
        let payload = EmergencyKit.qrPayload(secretKey: Self.secretKey)
        #expect(payload == "onepass-kit:1:" + Self.secretKey.replacingOccurrences(of: "-", with: ""))
        #expect(EmergencyKit.parsePayload(payload) == Self.secretKey)
        #expect(EmergencyKit.parsePayload(payload.lowercased()) == Self.secretKey)
    }

    @Test func parsePayloadRejectsForeignPayloads() {
        let bare = Self.secretKey.replacingOccurrences(of: "-", with: "")
        #expect(EmergencyKit.parsePayload("onepass-kit:2:" + bare) == nil)
        #expect(EmergencyKit.parsePayload("other:1:" + bare) == nil)
        #expect(EmergencyKit.parsePayload("onepass-kit:1:") == nil)
        #expect(EmergencyKit.parsePayload("onepass-kit:1:AAAQEAYE") == nil)
        #expect(EmergencyKit.parsePayload(bare) == nil)
        #expect(EmergencyKit.parsePayload("https://exemple.fr") == nil)
    }

    @Test func qrImageDecodes() throws {
        let image = try #require(EmergencyKit.qrImage(for: Self.secretKey, size: 300))
        #expect(image.width <= 300 && image.width >= 150)
        #expect(image.width == image.height)
        let detector = try #require(
            CIDetector(ofType: CIDetectorTypeQRCode, context: nil,
                       options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]))
        let features = detector.features(in: CIImage(cgImage: image))
        let message = (features.first as? CIQRCodeFeature)?.messageString
        #expect(message == EmergencyKit.qrPayload(secretKey: Self.secretKey))
    }

    @Test func qrImageIsNilForInvalidKey() {
        #expect(EmergencyKit.qrImage(for: "pas une cle", size: 200) == nil)
    }
}
