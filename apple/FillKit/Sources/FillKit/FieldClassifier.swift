import Foundation

public enum FieldKind: Sendable, Equatable {
    case password, username, oneTimeCode, other
}

public enum FieldClassifier {
    static let passwordKeywords: Set<String> = [
        "password", "passwd", "pwd", "mot de passe", "contraseña", "passwort", "密码", "비밀번호",
    ]
    static let oneTimeMarkers = ["one-time-code", "otp", "totp", "2fa"]
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
        for source in [f.domIdentifier].compactMap({ $0 }) + f.domClasses {
            let tokens = source.lowercased().split(whereSeparator: { "-_ ".contains($0) })
            let joined = tokens.map(String.init)
            if joined.contains(where: passwordKeywords.contains) { return true }
            // Keywords holding a space ("mot de passe") match across adjacent tokens.
            let phrase = joined.joined(separator: " ")
            if passwordKeywords.contains(where: { $0.contains(" ") && phrase.contains($0) }) {
                return true
            }
        }
        for text in [f.placeholder, f.label].compactMap({ $0 }) {
            if passwordKeywords.contains(normalized(text)) { return true }
        }
        return false
    }

    static func isOneTimeCode(_ f: FieldSnapshot) -> Bool {
        for source in [f.domIdentifier].compactMap({ $0 }) + f.domClasses {
            let s = source.lowercased()
            if oneTimeMarkers.contains(where: s.contains) { return true }
        }
        for text in [f.placeholder, f.label].compactMap({ $0 }) {
            if oneTimeLabels.contains(normalized(text)) { return true }
        }
        return false
    }

    private static func normalized(_ text: String) -> String {
        var s = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while let last = s.last, last == ":" || last == "*" {
            s.removeLast()
            s = s.trimmingCharacters(in: .whitespaces)
        }
        return s
    }
}
