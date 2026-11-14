import Foundation
import Testing

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
}
