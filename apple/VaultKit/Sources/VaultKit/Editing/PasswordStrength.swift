import Foundation

/// The one strength estimate of typed and stored passwords (master password, password fields, item
/// detail), the core's `passwordStrengthBits`: on the scale of `passwordEntropyBits(recipe:)`, so a
/// generated password shows the same level in the generator and once saved (a 5 word passphrase
/// is about 64.6 bits wherever it is shown). A hint, not a guarantee. Never logged.
public enum PasswordStrength {
    public static func estimatedBits(_ password: String) -> Double {
        password.isEmpty ? 0 : passwordStrengthBits(password: password)
    }

    /// The master password gate of the onboarding, separate from the meter's labels: five words
    /// drawn at random from a generator list (5 x log2(7776), about 64.6 bits) pass, four do not.
    public static let masterPasswordMinimumBits: Double = 64

    public static func acceptsMasterPassword(_ password: String) -> Bool {
        estimatedBits(password) >= masterPasswordMinimumBits
    }

    /// The "Générer" recipe of the master password step: five French words, hyphenated.
    public static let masterPasswordRecipe = FfiPasswordRecipe.words(
        count: 5, separator: "-", french: true, capitalize: false)
}
