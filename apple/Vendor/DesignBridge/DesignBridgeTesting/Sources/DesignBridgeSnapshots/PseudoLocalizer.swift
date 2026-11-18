import Foundation

/// Pseudo-localisation for truncation hunting.
///
/// Accents every ASCII letter, wraps the string in brackets and pads it so it grows by about
/// 40%, the usual worst case for French and German against English. Format specifiers
/// (`%@`, `%1$d`, `%.2f`, `%%`) and `{named}` placeholders are kept intact.
///
/// The brackets make clipping visible: if a snapshot shows `[Ŝéţţîñĝš` without the closing `]`,
/// the label was cut.
public struct PseudoLocalizer: Sendable, Hashable {
    /// Growth relative to the source length, 0.4 means 40%.
    public var expansion: Double
    public var brackets: Bool

    public init(expansion: Double = 0.4, brackets: Bool = true) {
        precondition(expansion >= 0, "expansion must not be negative")
        self.expansion = expansion
        self.brackets = brackets
    }

    public static let standard = PseudoLocalizer()

    static let accents: [Character: Character] = [
        "a": "á", "b": "ƀ", "c": "ç", "d": "ð", "e": "é", "f": "ƒ", "g": "ĝ", "h": "ĥ", "i": "î",
        "j": "ĵ", "k": "ķ", "l": "ļ", "m": "ɱ", "n": "ñ", "o": "ö", "p": "þ", "q": "ǫ", "r": "ŕ",
        "s": "š", "t": "ţ", "u": "û", "v": "ṽ", "w": "ŵ", "x": "ẋ", "y": "ý", "z": "ž",
        "A": "Å", "B": "Ɓ", "C": "Ç", "D": "Ð", "E": "É", "F": "Ƒ", "G": "Ĝ", "H": "Ĥ", "I": "Î",
        "J": "Ĵ", "K": "Ķ", "L": "Ļ", "M": "Ṁ", "N": "Ñ", "O": "Ö", "P": "Þ", "Q": "Ǫ", "R": "Ŕ",
        "S": "Š", "T": "Ţ", "U": "Û", "V": "Ṽ", "W": "Ŵ", "X": "Ẋ", "Y": "Ý", "Z": "Ž",
    ]

    /// Filler appended to reach the target length. Accented words so line breaking behaves like
    /// real text rather than one unbreakable run.
    static let filler = Array("ļöŕéɱ îþšûɱ ðöļöŕ šîţ áɱéţ çöñšéçţéţûŕ áðîþîšçîñĝ éļîţ ")

    static let placeholder = try! NSRegularExpression(
        pattern: #"%(?:\d+\$)?[-+ #0']*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|q|L|z|j|t)?[@dDiuUxXoOfFeEgGcCsSpaA%]|\{[^{}]*\}"#
    )

    /// The pseudo-localised form of `source`. An empty string stays empty.
    public func localize(_ source: String) -> String {
        guard !source.isEmpty else { return source }
        let ns = source as NSString
        var body = ""
        var cursor = 0
        var visible = 0
        for match in Self.placeholder.matches(in: source, range: NSRange(location: 0, length: ns.length)) {
            let before = ns.substring(with: NSRange(location: cursor, length: match.range.location - cursor))
            body += accent(before)
            visible += before.count
            body += ns.substring(with: match.range)
            cursor = match.range.location + match.range.length
        }
        let tail = ns.substring(from: cursor)
        body += accent(tail)
        visible += tail.count

        // Placeholders expand at runtime, so only literal text drives the growth target.
        let growth = Int((Double(max(visible, 1)) * expansion).rounded(.up))
        var padding = growth - (brackets ? 2 : 0)
        var result = body
        if padding > 0 {
            result += " "
            padding -= 1
            var i = 0
            while padding > 0 {
                result.append(Self.filler[i % Self.filler.count])
                i += 1
                padding -= 1
            }
        }
        return brackets ? "[\(result)]" : result
    }

    func accent(_ s: String) -> String {
        String(s.map { Self.accents[$0] ?? $0 })
    }
}
