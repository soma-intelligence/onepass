import Foundation

public enum FieldKind: Sendable, Equatable {
    case password, username, oneTimeCode, other
}

public enum FieldClassifier {
    static let passwordKeywords: [String] = [
        "password", "passwd", "pwd", "mot de passe", "contraseña", "passwort", "密码", "비밀번호",
    ]
    /// Whole-token markers (`footprint` and `hotpink` must not match `otp`). `2fa` splits at the
    /// letter/digit boundary, so it is a two-token sequence.
    static let oneTimeTokenMarkers: [[String]] = [["otp"], ["totp"], ["2", "fa"], ["one", "time", "code"]]
    static let oneTimeLabels: Set<String> = ["code", "verification code", "code de vérification"]

    /// `above` is the field right above `f`, kept for the helper's context. `below` is the next
    /// field: a plain text field with a password right below it is the username.
    public static func kind(
        _ f: FieldSnapshot, above: FieldSnapshot?, below: FieldSnapshot? = nil
    ) -> FieldKind {
        if isPassword(f) { return .password }
        if isOneTimeCode(f) { return .oneTimeCode }
        if f.role == "AXTextField", let below, isPassword(below) { return .username }
        return .other
    }

    static func isPassword(_ f: FieldSnapshot) -> Bool {
        if f.role == "AXSecureTextField" || f.subrole == "AXSecureTextField" { return true }
        let keywordTokens = passwordKeywords.map { tokens($0) }
        for source in domSources(f) {
            let t = tokens(source)
            if keywordTokens.contains(where: { containsSequence(t, $0) }) { return true }
        }
        for text in [f.placeholder, f.label].compactMap({ $0 }) {
            let n = normalized(text)
            if passwordKeywords.contains(where: { $0.precomposedStringWithCanonicalMapping == n }) {
                return true
            }
            // CJK scripts have no word boundaries: a keyword may sit inside a phrase.
            if passwordKeywords.contains(where: { isCJK($0) && n.contains($0) }) { return true }
        }
        return false
    }

    static func isOneTimeCode(_ f: FieldSnapshot) -> Bool {
        for source in domSources(f) {
            let lowered = source.precomposedStringWithCanonicalMapping.lowercased()
            if lowered.contains("one-time-code") || lowered.contains("one_time_code") { return true }
            let t = tokens(source)
            if oneTimeTokenMarkers.contains(where: { containsSequence(t, $0) }) { return true }
        }
        for text in [f.placeholder, f.label].compactMap({ $0 }) {
            if oneTimeLabels.contains(normalized(text)) { return true }
        }
        return false
    }

    private static func domSources(_ f: FieldSnapshot) -> [String] {
        [f.domIdentifier].compactMap { $0 } + f.domClasses
    }

    private static func containsSequence(_ haystack: [String], _ needle: [String]) -> Bool {
        guard !needle.isEmpty, haystack.count >= needle.count else { return false }
        for i in 0...(haystack.count - needle.count)
        where Array(haystack[i..<(i + needle.count)]) == needle {
            return true
        }
        return false
    }

    private static func isCJK(_ s: String) -> Bool {
        s.unicodeScalars.allSatisfy { $0.value >= 0x1100 }
    }

    private enum CharClass { case lower, upper, digit, letter, separator }

    /// Lowercased tokens, split on anything that is not a letter or digit, on camelCase
    /// boundaries (`userPassword`, `OTPCode`) and on letter/digit boundaries (`password1`).
    static func tokens(_ source: String) -> [String] {
        let chars = Array(source.precomposedStringWithCanonicalMapping)
        func cls(_ c: Character) -> CharClass {
            if c.isNumber { return .digit }
            if c.isLetter { return c.isUppercase ? .upper : (c.isLowercase ? .lower : .letter) }
            return .separator
        }
        var result: [String] = []
        var current = ""
        func flush() {
            if !current.isEmpty { result.append(current.lowercased()) }
            current = ""
        }
        for (i, c) in chars.enumerated() {
            let k = cls(c)
            if k == .separator { flush(); continue }
            if let prev = current.last.map(cls) {
                let boundary =
                    (prev == .lower && k == .upper)
                    || (prev == .digit) != (k == .digit)
                    || (prev == .upper && k == .upper && i + 1 < chars.count
                        && cls(chars[i + 1]) == .lower)
                if boundary { flush() }
            }
            current.append(c)
        }
        flush()
        return result
    }

    private static func normalized(_ text: String) -> String {
        var s = text.precomposedStringWithCanonicalMapping
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while let last = s.last, last == ":" || last == "*" {
            s.removeLast()
            s = s.trimmingCharacters(in: .whitespaces)
        }
        return s
    }
}
