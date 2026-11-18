import SwiftUI

/// How a `DBNumber` is written. Always locale aware (UX-NUM-03).
public enum DBNumberFormat: Sendable, Hashable {
    /// Whole number with grouping: 1,234.
    case integer
    /// Fixed fraction digits: 1,234.50.
    case decimal(fractionDigits: Int)
    /// ISO 4217 currency, with the currency's own fraction digits unless given.
    case currency(code: String, fractionDigits: Int? = nil)
    /// 0.25 reads as 25%.
    case percent(fractionDigits: Int = 0)
}

/// The pure formatting behind `DBNumber`, exposed for tests and for accessibility values.
public enum DBNumberFormatting {
    public static func string(_ value: Double, format: DBNumberFormat, locale: Locale) -> String {
        switch format {
        case .integer:
            return value.formatted(.number.precision(.fractionLength(0)).locale(locale))
        case .decimal(let digits):
            return value.formatted(.number.precision(.fractionLength(max(0, digits))).locale(locale))
        case .currency(let code, let digits):
            let style = FloatingPointFormatStyle<Double>.Currency(code: code, locale: locale)
            if let digits {
                return value.formatted(style.precision(.fractionLength(max(0, digits))))
            }
            return value.formatted(style)
        case .percent(let digits):
            return value.formatted(.percent.precision(.fractionLength(max(0, digits))).locale(locale))
        }
    }
}

/// A number that rolls digit by digit when it changes (UX-NUM-01), with
/// tabular digits (UX-NUM-02) and one shared spring (`DBMotion.number`).
/// Under Reduce Motion the change crossfades (UX-MOT-03).
///
/// ```swift
/// DBNumber(steps)
/// DBNumber(score, format: .decimal(fractionDigits: 1))
/// DBNumber(balance, currencyCode: "EUR")
/// ```
///
/// The value changes on its own; no `withAnimation` is needed at the call site.
public struct DBNumber: View {
    private let value: Double
    private let format: DBNumberFormat

    @Environment(\.locale) private var locale
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    public init(_ value: Int) {
        self.value = Double(value)
        self.format = .integer
    }

    public init(_ value: Double, format: DBNumberFormat = .decimal(fractionDigits: 2)) {
        self.value = value
        self.format = format
    }

    public init(_ value: Double, currencyCode: String) {
        self.value = value
        self.format = .currency(code: currencyCode)
    }

    public var body: some View {
        Text(DBNumberFormatting.string(value, format: format, locale: locale))
            .monospacedDigit()
            .dbRollingNumber(value: value, reduceMotion: reduceMotion)
    }
}

public extension View {
    /// Applies the `DBNumber` transition to any `Text` showing `value`.
    func dbRollingNumber(value: Double) -> some View {
        modifier(DBRollingNumberModifier(value: value))
    }

    fileprivate func dbRollingNumber(value: Double, reduceMotion: Bool) -> some View {
        self
            .contentTransition(reduceMotion ? .opacity : .numericText(value: value))
            .animation(DBMotion.number.animation(reduceMotion: reduceMotion), value: value)
    }
}

private struct DBRollingNumberModifier: ViewModifier {
    let value: Double
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content
            .monospacedDigit()
            .dbRollingNumber(value: value, reduceMotion: reduceMotion)
    }
}
