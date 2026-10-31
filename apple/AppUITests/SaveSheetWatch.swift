import XCTest

/// Watches for the system "Save Password?" sheet (iOS offering to copy a typed secret into the
/// system password manager), which OnePass must never trigger (ruling X24 of the milestone 3 spec).
@MainActor
enum SaveSheetWatch {
    /// Texts of the sheet, in English (a fresh simulator) and in French.
    static let titles = ["Save Password?", "Enregistrer le mot de passe ?", "Enregistrer le mot de passe\u{00A0}?"]
    static let buttons = ["Not Now", "Pas maintenant", "Save", "Save Password", "Enregistrer le mot de passe"]

    /// Polls the app and SpringBoard for `seconds` (the sheet fades in 1 to 4 s after a filled
    /// secure field leaves the screen). Returns the first sheet text found, with where it was, or
    /// nil when the whole window passed without it.
    static func firstSighting(in app: XCUIApplication, for seconds: TimeInterval = 10) -> String? {
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let deadline = Date().addingTimeInterval(seconds)
        repeat {
            for (name, target) in [("app", app), ("springboard", springboard)] {
                if let found = text(in: target) { return "\"\(found)\" in \(name)" }
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.4))
        } while Date() < deadline
        return nil
    }

    /// "Not Now", so a test that records a sighting can go on.
    static func refuse(in app: XCUIApplication) {
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let refusal = NSPredicate(format: "label IN %@", ["Not Now", "Pas maintenant"])
        for target in [app, springboard] {
            let notNow = target.buttons.matching(refusal).firstMatch
            if notNow.exists {
                notNow.tap()
                _ = notNow.waitForNonExistence(timeout: 5)
            }
        }
    }

    private static func text(in target: XCUIApplication) -> String? {
        let title = target.staticTexts.matching(NSPredicate(format: "label IN %@", titles)).firstMatch
        if title.exists { return title.label }
        let button = target.buttons.matching(NSPredicate(format: "label IN %@", buttons)).firstMatch
        if button.exists { return button.label }
        return nil
    }
}
