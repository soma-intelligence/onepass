import Foundation
import Testing
import UniformTypeIdentifiers

@testable import VaultKit

@Suite("OTP scan")
struct OtpScanTests {
    @Test func scanAcceptsOtpauth() {
        let uri = "otpauth://totp/Exemple:camille?secret=JBSWY3DPEHPK3PXP&issuer=Exemple"
        guard case .value(let value) = OtpScan.read(uri) else {
            Issue.record("expected a value")
            return
        }
        #expect(value.hasPrefix("otpauth://totp/"))
        #expect(value.contains("JBSWY3DPEHPK3PXP"))
    }

    /// Google Authenticator export of two accounts (the one-account export of `OtpLinkTests`, twice).
    static let twoAccounts =
        "otpauth-migration://offline?data=CjQKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEg5HaXRIdWI6cXVlbnRpbhoGR2l0SHViIAEoATACCjQKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEg5HaXRIdWI6cXVlbnRpbhoGR2l0SHViIAEoATAC"

    @Test func scanAcceptsOneAccountExport() {
        let one = "otpauth-migration://offline?data=CjQKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEg5HaXRIdWI6cXVlbnRpbhoGR2l0SHViIAEoATAC"
        guard case .value(let value) = OtpScan.read(one) else {
            Issue.record("expected a value")
            return
        }
        #expect(value.hasPrefix("otpauth://"))
    }

    @Test func scanRejectsMultiAndForeign() {
        #expect(OtpScan.read(Self.twoAccounts) == .severalAccounts(2))
        #expect(OtpScan.read("https://exemple.fr") == .notOtp)
        #expect(OtpScan.read("bonjour") == .notOtp)
        #expect(OtpScan.read("otpauth-migration://offline?data=%%%") == .notOtp)
    }

    /// A file dragged from the Finder may carry only its URL: the image is read from the file.
    @Test func droppedFileURLGivesTheImageData() async throws {
        let bytes = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3])
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("otp-drop-\(UUID()).png")
        try bytes.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let provider = NSItemProvider()
        provider.registerDataRepresentation(forTypeIdentifier: UTType.fileURL.identifier, visibility: .all) { done in
            done(url.dataRepresentation, nil)
            return nil
        }
        #expect(await OtpScan.imageData(from: provider) == bytes)
    }

    @Test func droppedImageDataIsKept() async {
        let bytes = Data([0x89, 0x50, 0x4E, 0x47, 9])
        let provider = NSItemProvider()
        provider.registerDataRepresentation(forTypeIdentifier: UTType.png.identifier, visibility: .all) { done in
            done(bytes, nil)
            return nil
        }
        #expect(await OtpScan.imageData(from: provider) == bytes)
    }
}
