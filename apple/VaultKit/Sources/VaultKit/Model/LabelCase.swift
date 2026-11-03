import Foundation

/// How a field or section label is written above its value. French keeps the house lowercase
/// ("mot de passe"); English, Spanish and Italian start with a capital, as their own rules want, so an
/// English label never reads like a raw field id ("username"). An acronym first ("PIN", "URL") stays.
public enum LabelCase {
    /// The language the app shows, from the main bundle's localizations.
    public static var currentLanguage: String { Bundle.main.preferredLocalizations.first ?? "en" }

    public static func detail(_ label: String, language: String = currentLanguage) -> String {
        guard let first = label.first else { return label }
        if let second = label.dropFirst().first, first.isUppercase, second.isUppercase { return label }
        if language.lowercased().hasPrefix("fr") {
            return first.isUppercase ? first.lowercased() + label.dropFirst() : label
        }
        return first.isLowercase ? first.uppercased() + label.dropFirst() : label
    }
}
