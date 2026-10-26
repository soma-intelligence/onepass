import Foundation

/// Rough entropy of a typed password, for the strength meter (a generated one uses the core's
/// `passwordEntropyBits(recipe:)`): length times log2 of the character pool it draws from.
/// Overestimates words and patterns; a hint, not a guarantee. Never logged.
public enum PasswordStrength {
    public static func estimatedBits(_ password: String) -> Double {
        guard !password.isEmpty else { return 0 }
        var pool = 0
        var lower = false, upper = false, digit = false, symbol = false, other = false
        for scalar in password.unicodeScalars {
            switch scalar.value {
            case 0x61...0x7A: lower = true
            case 0x41...0x5A: upper = true
            case 0x30...0x39: digit = true
            case 0x21...0x7E, 0x20: symbol = true
            default: other = true
            }
        }
        if lower { pool += 26 }
        if upper { pool += 26 }
        if digit { pool += 10 }
        if symbol { pool += 33 }
        if other { pool += 100 }
        return Double(password.count) * log2(Double(pool))
    }
}
