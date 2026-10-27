import SwiftUI
import VaultKit

/// Amounts are stored in minor units (cents) with an ISO currency code.
enum Money {
    static let defaultCurrency = "EUR"

    static func amount(minorUnits: Int64) -> Decimal { Decimal(minorUnits) / 100 }

    static func minorUnits(_ amount: Decimal) -> Int64 {
        var scaled = amount * 100
        var rounded = Decimal()
        NSDecimalRound(&rounded, &scaled, 0, .plain)
        return NSDecimalNumber(decimal: rounded).int64Value
    }

    /// "12,50 €".
    static func formatted(minorUnits: Int64, currency: String) -> String {
        let code = currency.isEmpty ? defaultCurrency : currency
        return amount(minorUnits: minorUnits).formatted(.currency(code: code).locale(FieldDates.french))
    }
}

/// A text field parsed on every keystroke (pads without Return never lose the value): the value
/// follows the text when it reads as a number, and goes back to empty when the text is cleared.
struct ParsedTextField<V: Equatable>: View {
    let title: String
    let prompt: String
    let kind: FfiFieldType
    let value: V?
    let parse: (String) -> V?
    let format: (V) -> String
    let commit: (V?) -> Void
    @State private var text = ""

    var body: some View {
        TextField(title, text: $text, prompt: Text(prompt))
            .fieldInput(kind)
            .onAppear { text = value.map(format) ?? "" }
            .onChange(of: text) { _, new in
                let trimmed = new.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty {
                    commit(nil)
                } else if let parsed = parse(trimmed), parsed != value {
                    commit(parsed)
                }
            }
            .onChange(of: value) { _, new in
                // Changed from elsewhere (cleared, generated): show it unless the text already says it.
                if parse(text) != new { text = new.map(format) ?? "" }
            }
    }
}

/// Whole number field.
struct NumberEditor: View {
    let field: FfiField
    @Binding var value: FfiFieldValue

    private var number: Int64? { if case .number(let n) = value { n } else { nil } }

    var body: some View {
        ParsedTextField(
            title: field.displayLabel, prompt: "", kind: .number, value: number,
            parse: NumberInput.integer, format: { String($0) },
            commit: { value = $0.map { .number(value: $0) } ?? .empty })
            .accessibilityIdentifier("editor.field.\(field.id)")
    }
}

/// Amount and currency (uppercase letters, three at most).
struct MoneyEditor: View {
    let field: FfiField
    @Binding var value: FfiFieldValue
    @State private var pendingCurrency = Money.defaultCurrency

    private var parts: (minor: Int64, currency: String)? {
        if case .money(let minor, let currency) = value { (minor, currency) } else { nil }
    }

    private var currency: Binding<String> {
        Binding(
            get: { parts?.currency ?? pendingCurrency },
            set: { code in
                let cleaned = String(code.uppercased().filter { $0.isASCII && $0.isLetter }.prefix(3))
                pendingCurrency = cleaned
                if let parts { value = .money(minorUnits: parts.minor, currency: cleaned) }
            })
    }

    var body: some View {
        HStack {
            ParsedTextField(
                title: field.displayLabel, prompt: "0,00", kind: .money,
                value: parts.map { Money.amount(minorUnits: $0.minor) },
                parse: NumberInput.decimal, format: NumberInput.text,
                commit: { amount in
                    let code = parts?.currency ?? pendingCurrency
                    value = amount.map { .money(minorUnits: Money.minorUnits($0), currency: code) } ?? .empty
                })
                .accessibilityIdentifier("editor.field.\(field.id)")
            TextField("Devise", text: currency)
                .frame(maxWidth: 64)
                .multilineTextAlignment(.trailing)
                .fieldInput(.text)
                #if os(iOS) || os(visionOS)
                .textInputAutocapitalization(.characters)
                #endif
                .accessibilityLabel(Text("Devise"))
        }
    }
}
