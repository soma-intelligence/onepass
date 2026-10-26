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

/// Whole number field.
struct NumberEditor: View {
    let field: FfiField
    @Binding var value: FfiFieldValue

    private var number: Binding<Int64?> {
        Binding(
            get: { if case .number(let n) = value { n } else { nil } },
            set: { value = $0.map { .number(value: $0) } ?? .empty })
    }

    var body: some View {
        TextField(field.label, value: number, format: .number.grouping(.never), prompt: Text("0"))
            .fieldInput(.number)
            .accessibilityIdentifier("editor.field.\(field.id)")
    }
}

/// Amount and currency.
struct MoneyEditor: View {
    let field: FfiField
    @Binding var value: FfiFieldValue

    private var parts: (minor: Int64, currency: String)? {
        if case .money(let minor, let currency) = value { (minor, currency) } else { nil }
    }

    private var amount: Binding<Decimal?> {
        Binding(
            get: { parts.map { Money.amount(minorUnits: $0.minor) } },
            set: { new in
                let currency = parts?.currency ?? Money.defaultCurrency
                value = new.map { .money(minorUnits: Money.minorUnits($0), currency: currency) } ?? .empty
            })
    }

    private var currency: Binding<String> {
        Binding(
            get: { parts?.currency ?? Money.defaultCurrency },
            set: { code in
                let cleaned = String(code.uppercased().filter(\.isLetter).prefix(3))
                if let parts { value = .money(minorUnits: parts.minor, currency: cleaned) }
            })
    }

    var body: some View {
        HStack {
            TextField(
                field.label, value: amount, format: .number.precision(.fractionLength(0...2)).locale(FieldDates.french),
                prompt: Text("0,00")
            )
            .fieldInput(.money)
            .accessibilityIdentifier("editor.field.\(field.id)")
            TextField("Devise", text: currency)
                .frame(maxWidth: 64)
                .multilineTextAlignment(.trailing)
                .fieldInput(.text)
                .disabled(parts == nil)
                .accessibilityLabel(Text("Devise"))
        }
    }
}
