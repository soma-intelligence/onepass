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

    @Test func pdfStartsWithAccessWarningAndAsksToPrint() throws {
        let data = try EmergencyKit.pdf(
            secretKey: Self.secretKey, accountID: Self.accountID,
            displayName: "Camille Durand", createdAt: Date(timeIntervalSince1970: 1_800_000_000))
        let document = try #require(PDFDocument(data: data))
        let text = try #require(document.string)
        let flat = text.split(whereSeparator: \.isWhitespace).joined(separator: " ")
        let warning = "Ce kit plus ton mot de passe maître donnent un accès complet à ton coffre."
        #expect(flat.contains(warning))
        // The warning comes before the Secret Key heading.
        let warningRange = try #require(flat.range(of: warning))
        let keyRange = try #require(flat.range(of: "Ta Secret Key"))
        #expect(warningRange.lowerBound < keyRange.lowerBound)
        #expect(!flat.contains("Ne l'imprime pas"))
        #expect(flat.contains("Imprime"))
        #expect(flat.contains("hors ligne"))
        #expect(flat.contains("photographie"))
        #expect(!text.contains("\u{2014}"))
    }

    // MARK: Temporary file

    private static func scratchFolder() throws -> URL {
        let folder = FileManager.default.temporaryDirectory
            .appendingPathComponent("vaultkit-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder
    }

    @Test func temporaryFileIsExcludedFromBackup() throws {
        let parent = try Self.scratchFolder()
        defer { try? FileManager.default.removeItem(at: parent) }
        let data = Data("%PDF-1.4 test".utf8)
        let file = try EmergencyKitFile.write(data, under: parent)
        defer { EmergencyKitFile.remove(file, under: parent) }
        #expect(file.lastPathComponent == "Emergency Kit OnePass.pdf")
        #expect(file.deletingLastPathComponent().deletingLastPathComponent().standardizedFileURL.path
            == parent.standardizedFileURL.path)
        #expect(file.deletingLastPathComponent().lastPathComponent.hasPrefix("kit-"))
        #expect(try Data(contentsOf: file) == data)
        let fileValues = try file.resourceValues(forKeys: [.isExcludedFromBackupKey])
        #expect(fileValues.isExcludedFromBackup == true)
        let folderValues = try file.deletingLastPathComponent()
            .resourceValues(forKeys: [.isExcludedFromBackupKey])
        #expect(folderValues.isExcludedFromBackup == true)
    }

    @Test func removeDeletesTheKitFolder() throws {
        let parent = try Self.scratchFolder()
        defer { try? FileManager.default.removeItem(at: parent) }
        let file = try EmergencyKitFile.write(Data("x".utf8), under: parent)
        EmergencyKitFile.remove(file, under: parent)
        #expect(!FileManager.default.fileExists(atPath: file.deletingLastPathComponent().path))
        #expect(FileManager.default.fileExists(atPath: parent.path))
    }

    @Test func removeRefusesForeignKitFolders() throws {
        let parent = try Self.scratchFolder()
        let elsewhere = try Self.scratchFolder()
        defer {
            try? FileManager.default.removeItem(at: parent)
            try? FileManager.default.removeItem(at: elsewhere)
        }
        // A kit folder under another root is left alone.
        let foreign = try EmergencyKitFile.write(Data("x".utf8), under: elsewhere)
        EmergencyKitFile.remove(foreign, under: parent)
        #expect(FileManager.default.fileExists(atPath: foreign.path))
        // A kit-* folder under the right root but holding another file name is left alone.
        let folder = parent.appendingPathComponent("kit-autre", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let other = folder.appendingPathComponent("notes.pdf")
        try Data("x".utf8).write(to: other)
        EmergencyKitFile.remove(other, under: parent)
        #expect(FileManager.default.fileExists(atPath: other.path))
        // A folder without the kit prefix is left alone.
        let plain = parent.appendingPathComponent("documents", isDirectory: true)
        try FileManager.default.createDirectory(at: plain, withIntermediateDirectories: true)
        let named = plain.appendingPathComponent(EmergencyKitFile.fileName)
        try Data("x".utf8).write(to: named)
        EmergencyKitFile.remove(named, under: parent)
        #expect(FileManager.default.fileExists(atPath: named.path))
    }

    @Test func sweepRemovesOnlyKitFolders() throws {
        let parent = try Self.scratchFolder()
        defer { try? FileManager.default.removeItem(at: parent) }
        let file = try EmergencyKitFile.write(Data("x".utf8), under: parent)
        let other = parent.appendingPathComponent("other", isDirectory: true)
        try FileManager.default.createDirectory(at: other, withIntermediateDirectories: true)
        EmergencyKitFile.sweep(in: parent)
        #expect(!FileManager.default.fileExists(atPath: file.path))
        #expect(FileManager.default.fileExists(atPath: other.path))
    }

    // MARK: Sharing

    @Test func shareExcludesPhotosPasteboardContactsReadingListAndMessaging() {
        let excluded = Set(EmergencyKitSharing.excludedActivityTypes)
        for type in [
            "com.apple.UIKit.activity.SaveToCameraRoll",
            "com.apple.UIKit.activity.CopyToPasteboard",
            "com.apple.UIKit.activity.AssignToContact",
            "com.apple.UIKit.activity.AddToReadingList",
            "com.apple.UIKit.activity.Message",
            "com.apple.UIKit.activity.Mail",
            "com.apple.UIKit.activity.PostToFacebook",
            "com.apple.UIKit.activity.PostToTwitter",
            "com.apple.UIKit.activity.PostToWeibo",
            "com.apple.UIKit.activity.TencentWeibo",
            "com.apple.UIKit.activity.PostToFlickr",
            "com.apple.UIKit.activity.PostToVimeo",
            "com.apple.UIKit.activity.CollaborationCopyLink",
            "com.apple.UIKit.activity.CollaborationInviteWithLink",
        ] {
            #expect(excluded.contains(type), "\(type) must be excluded")
        }
        #expect(!excluded.contains("com.apple.UIKit.activity.Print"))
        #expect(!excluded.contains("com.apple.UIKit.activity.AirDrop"))
    }

    // MARK: Destination

    @Test func iCloudDrivePathsAreCloudSynced() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let urls = [
            "\(home)/Library/Mobile Documents/com~apple~CloudDocs/Emergency Kit OnePass.pdf",
            "\(home)/Library/Mobile Documents/com~apple~CloudDocs/Dossier/kit.pdf",
            "/private/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/kit.pdf",
            "\(home)/Library/CloudStorage/Dropbox/kit.pdf",
            "\(home)/Library/CloudStorage/GoogleDrive-camille@exemple.fr/Mon Drive/kit.pdf",
            "\(home)/Library/CloudStorage/OneDrive-Personnel/kit.pdf",
        ].map { URL(fileURLWithPath: $0) }
        for url in urls {
            #expect(KitDestination.isCloudSynced(url), "\(url.path)")
        }
    }

    @Test func localPathsAreNotCloudSynced() throws {
        let parent = try Self.scratchFolder()
        defer { try? FileManager.default.removeItem(at: parent) }
        let existing = parent.appendingPathComponent("kit.pdf")
        try Data("x".utf8).write(to: existing)
        #expect(!KitDestination.isCloudSynced(existing))
        #expect(!KitDestination.isCloudSynced(parent.appendingPathComponent("absent.pdf")))
        #expect(!KitDestination.isCloudSynced(URL(fileURLWithPath: "/Volumes/USB/kit.pdf")))
        #expect(!KitDestination.isCloudSynced(URL(fileURLWithPath: "/Users/camille/Documents/Mobile Documents.pdf")))
        #expect(!KitDestination.isCloudSynced(URL(fileURLWithPath: "/Users/camille/Documents/CloudStorage/kit.pdf")))
        #expect(!KitDestination.isCloudSynced(URL(string: "https://exemple.fr/kit.pdf")!))
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
