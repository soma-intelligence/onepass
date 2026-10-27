import Foundation

/// VaultKit's own string catalogs: `Resources/Localizable.xcstrings` for messages and
/// `Resources/CoreLabels.xcstrings` for the core's template text. French is the source language.
enum VaultKitStrings {
    /// The bundle every VaultKit string is read from. Tests that compare French text call
    /// `pinSourceLanguage()` so they pass whatever the language of the machine.
    nonisolated(unsafe) static var bundle: Bundle = .module

    /// Reads strings from the French localization only (tests). Idempotent.
    static func pinSourceLanguage() {
        if let path = Bundle.module.path(forResource: "fr", ofType: "lproj"), let fr = Bundle(path: path) {
            bundle = fr
        }
    }
}
