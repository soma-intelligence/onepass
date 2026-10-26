import Foundation

/// The one strength estimate of typed and stored passwords (master password, password fields, item
/// detail), the core's `passwordStrengthBits`: on the scale of `passwordEntropyBits(recipe:)`, so a
/// generated password shows the same level in the generator and once saved (a 5 word passphrase
/// is about 64.6 bits wherever it is shown). A hint, not a guarantee. Never logged.
public enum PasswordStrength {
    public static func estimatedBits(_ password: String) -> Double {
        password.isEmpty ? 0 : passwordStrengthBits(password: password)
    }
}
