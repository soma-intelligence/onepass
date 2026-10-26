import Foundation

/// Parses what the user types in number, amount and coordinate fields, on every keystroke:
/// a leading minus, "," or "." as the decimal separator, spaces (including the French narrow
/// no-break space) ignored. Nil when the text is not a number (yet).
public enum NumberInput {
    /// Spaces and the separators a French locale prints between thousands.
    private static let ignored: Set<Character> = [" ", "\u{00A0}", "\u{202F}", "'"]

    private static func cleaned(_ text: String) -> String {
        String(text.filter { !ignored.contains($0) }).replacingOccurrences(of: ",", with: ".")
    }

    /// "-12,5" gives -12.5. One separator at most, digits required.
    public static func decimal(_ text: String) -> Decimal? {
        let s = cleaned(text)
        guard isNumber(s, allowFraction: true) else { return nil }
        return Decimal(string: s, locale: Locale(identifier: "en_US_POSIX"))
    }

    public static func double(_ text: String) -> Double? {
        let s = cleaned(text)
        guard isNumber(s, allowFraction: true) else { return nil }
        return Double(s)
    }

    /// Whole numbers only ("1 250" gives 1250); nil on overflow.
    public static func integer(_ text: String) -> Int64? {
        let s = cleaned(text)
        guard isNumber(s, allowFraction: false) else { return nil }
        return Int64(s)
    }

    private static func isNumber(_ s: String, allowFraction: Bool) -> Bool {
        var body = Substring(s)
        if body.first == "-" { body = body.dropFirst() }
        let parts = body.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 1 || (allowFraction && parts.count == 2) else { return false }
        guard parts.allSatisfy({ $0.allSatisfy(\.isASCII) && $0.allSatisfy(\.isNumber) }) else { return false }
        // "12." and ".5" are fine while typing, "." alone is not.
        return parts.contains { !$0.isEmpty }
    }

    /// Text for a decimal in the editor: French comma, no grouping ("-12,5").
    public static func text(_ value: Decimal) -> String {
        NSDecimalNumber(decimal: value).stringValue.replacingOccurrences(of: ".", with: ",")
    }

    /// Text for a coordinate: up to 6 decimals, comma ("48,85661").
    public static func text(_ value: Double) -> String {
        var s = String(format: "%.6f", value)
        while s.hasSuffix("0") { s.removeLast() }
        if s.hasSuffix(".") { s.removeLast() }
        return s.replacingOccurrences(of: ".", with: ",")
    }
}
