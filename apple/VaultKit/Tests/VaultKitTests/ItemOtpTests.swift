import Foundation
import Testing

@testable import VaultKit

@Suite("Item OTP")
struct ItemOtpTests {
    @Test func firstOtpValueSkipsEmpty() {
        var login = draftItem(.login)
        let main = login.sections.firstIndex { $0.id == "main" }!
        let totp = login.sections[main].fields.firstIndex { $0.id == "totp" }!
        login.sections[main].fields[totp].value = .otp(value: "")
        login.sections.append(
            FfiSection(
                id: "custom", label: "Autre", fields: [
                    FfiField(
                        id: "code", label: "Code du portail", kind: .otp,
                        value: .otp(value: "JBSWY3DPEHPK3PXP"), required: false, repeatable: false,
                        autofill: false)
                ]))
        #expect(firstOtpValue(of: login) == "JBSWY3DPEHPK3PXP")

        // Whitespace only counts as empty.
        login.sections[main].fields[totp].value = .otp(value: "  ")
        #expect(firstOtpValue(of: login) == "JBSWY3DPEHPK3PXP")
        // Both filled: the first in section order wins.
        login.sections[main].fields[totp].value = .otp(value: "otpauth://totp/Forge?secret=GEZDGNBV")
        #expect(firstOtpValue(of: login) == "otpauth://totp/Forge?secret=GEZDGNBV")

        #expect(firstOtpValue(of: draftItem(.login)) == nil)
        #expect(firstOtpValue(of: draftItem(.secureNote)) == nil)
    }

    @Test func firstPasswordFieldSkipsEmpty() {
        var login = draftItem(.login)
        #expect(firstPasswordField(of: login) == nil)
        login.sections.append(
            FfiSection(
                id: "custom", label: "Autre", fields: [
                    FfiField(
                        id: "pin", label: "Code du portail", kind: .password,
                        value: .password(value: "4321"), required: false, repeatable: false,
                        autofill: false)
                ]))
        #expect(firstPasswordField(of: login)?.id == "pin")

        // The main password, once filled, comes first.
        let main = login.sections.firstIndex { $0.id == "main" }!
        let password = login.sections[main].fields.firstIndex { $0.kind == .password }!
        login.sections[main].fields[password].value = .password(value: "hunter2")
        #expect(firstPasswordField(of: login)?.value == .password(value: "hunter2"))

        #expect(firstPasswordField(of: draftItem(.secureNote)) == nil)
    }
}
