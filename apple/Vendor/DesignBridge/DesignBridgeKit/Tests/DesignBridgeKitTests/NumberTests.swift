import Foundation
import Testing
@testable import DesignBridgeKit

/// Normalises the no-break spaces ICU uses so expectations stay readable.
private func plain(_ string: String) -> String {
    string
        .replacingOccurrences(of: "\u{00A0}", with: " ")
        .replacingOccurrences(of: "\u{202F}", with: " ")
        .replacingOccurrences(of: "\u{2212}", with: "-")
}

private let us = Locale(identifier: "en_US")
private let fr = Locale(identifier: "fr_FR")
private let de = Locale(identifier: "de_DE")

@Suite("Number formatting (UX-NUM-03)")
struct NumberFormattingTests {
    @Test func integerGroupsByLocale() {
        #expect(DBNumberFormatting.string(1_234_567, format: .integer, locale: us) == "1,234,567")
        #expect(plain(DBNumberFormatting.string(1_234_567, format: .integer, locale: fr)) == "1 234 567")
        #expect(DBNumberFormatting.string(1_234_567, format: .integer, locale: de) == "1.234.567")
    }

    @Test func integerRoundsFractions() {
        #expect(DBNumberFormatting.string(41.6, format: .integer, locale: us) == "42")
    }

    @Test func decimalKeepsFixedFractionDigits() {
        #expect(DBNumberFormatting.string(3.1, format: .decimal(fractionDigits: 2), locale: us) == "3.10")
        #expect(DBNumberFormatting.string(3.1, format: .decimal(fractionDigits: 2), locale: de) == "3,10")
        #expect(DBNumberFormatting.string(3.14159, format: .decimal(fractionDigits: 0), locale: us) == "3")
    }

    @Test func negativeDecimalNeverLosesItsSign() {
        #expect(plain(DBNumberFormatting.string(-2.5, format: .decimal(fractionDigits: 1), locale: us)) == "-2.5")
    }

    @Test func currencyFollowsLocale() {
        #expect(DBNumberFormatting.string(1_234.5, format: .currency(code: "USD"), locale: us) == "$1,234.50")
        #expect(plain(DBNumberFormatting.string(1_234.5, format: .currency(code: "EUR"), locale: fr)) == "1 234,50 €")
        #expect(plain(DBNumberFormatting.string(1_234.5, format: .currency(code: "EUR"), locale: de)) == "1.234,50 €")
    }

    @Test func currencyUsesItsOwnFractionDigits() {
        #expect(DBNumberFormatting.string(1_234, format: .currency(code: "JPY"), locale: us) == "¥1,234")
    }

    @Test func currencyFractionDigitsOverride() {
        #expect(DBNumberFormatting.string(1_234.56, format: .currency(code: "USD", fractionDigits: 0), locale: us) == "$1,235")
    }

    @Test func negativeCurrency() {
        #expect(plain(DBNumberFormatting.string(-20, format: .currency(code: "USD"), locale: us)) == "-$20.00")
    }

    @Test func percent() {
        #expect(DBNumberFormatting.string(0.25, format: .percent(), locale: us) == "25%")
        #expect(DBNumberFormatting.string(0.256, format: .percent(fractionDigits: 1), locale: us) == "25.6%")
        #expect(plain(DBNumberFormatting.string(0.25, format: .percent(), locale: fr)) == "25 %")
    }

    @Test func negativeFractionDigitsAreTreatedAsZero() {
        #expect(DBNumberFormatting.string(2.6, format: .decimal(fractionDigits: -3), locale: us) == "3")
    }
}
