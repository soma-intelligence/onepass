import Foundation

/// DesignKit's own string catalog (`Resources/Localizable.xcstrings`). French is the source language.
enum DesignKitStrings {
    /// The bundle DesignKit's plain strings are read from. Tests that compare French text call
    /// `pinSourceLanguage()` so they pass whatever the language of the machine.
    nonisolated(unsafe) static var bundle: Bundle = .module

    /// Reads strings from the French localization only (tests). Idempotent.
    static func pinSourceLanguage() {
        if let path = Bundle.module.path(forResource: "fr", ofType: "lproj"), let fr = Bundle(path: path) {
            bundle = fr
        }
    }
}
