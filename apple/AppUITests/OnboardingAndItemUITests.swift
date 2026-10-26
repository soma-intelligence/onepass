import XCTest

/// End-to-end flow on the iPhone simulator (spec 10): create an account with the real Argon2id
/// (256 MiB), add a Login, find it by search, lock, unlock with the master password.
/// Fictional data only (`exemple.fr`, Camille Durand, Projet Atlas).
@MainActor
final class OnboardingAndItemUITests: XCTestCase {
    private static let password = "ruisseau-tapis-orage-comète"
    private static let title = "Exemple Atlas"
    private static let username = "camille.durand@exemple.fr"

    /// Account creation and unlock run Argon2id 256 MiB: the real cost, never lowered for the test.
    private static let kdfTimeout: TimeInterval = 90
    private static let uiTimeout: TimeInterval = 15

    override func setUp() async throws {
        continueAfterFailure = false
    }

    func testCreateAccountAddLoginLockUnlock() throws {
        let app = XCUIApplication()
        // Debug only: empties the store, the settings and this app's keychain items first.
        app.launchArguments += ["-OnePassUITestReset", "YES"]
        app.launch()

        // Bienvenue, then "Cet appareil est-il à toi ?" (personal, the default).
        tap(app.buttons["onboarding.create"])
        tap(app.buttons["onboarding.primary"])

        // Mot de passe maître.
        type(Self.password, into: app.secureTextFields["onboarding.password"])
        type(Self.password, into: app.secureTextFields["onboarding.confirm"])
        tap(app.buttons["onboarding.primary"])

        // Secret Key and Emergency Kit: shown once the account exists (Argon2id).
        let kitStored = app.buttons["onboarding.kitStored"]
        XCTAssertTrue(kitStored.waitForExistence(timeout: Self.kdfTimeout), "account not created")
        tap(kitStored)
        tap(app.buttons["onboarding.primary"])

        // Biometrics: "Plus tard" (the step is skipped where no Secure Enclave is available).
        let later = app.buttons["onboarding.skip"]
        if later.waitForExistence(timeout: 3) { tap(later) }

        // Terminé: "Ouvrir OnePass".
        let open = app.buttons["onboarding.primary"]
        XCTAssertTrue(open.waitForExistence(timeout: Self.uiTimeout))
        XCTAssertEqual(open.label, "Ouvrir OnePass")
        tap(open)

        // New Login.
        tap(app.buttons["items.new"])
        tap(app.buttons["newItem.login"])
        // Return closes the keyboard so the next fields are on screen.
        type(Self.title + "\n", into: app.textFields["editor.title"])
        type(Self.username + "\n", into: app.textFields["editor.field.username"])
        tap(app.buttons["editor.generate.password"])
        let generated = app.staticTexts["generator.value"]
        XCTAssertTrue(generated.waitForExistence(timeout: Self.uiTimeout))
        XCTAssertFalse(generated.label.trimmingCharacters(in: .whitespaces).isEmpty, "no password generated")
        tap(app.buttons["generator.use"])
        // The generated password is in the field (a secure field shows bullets).
        let passwordField = app.secureTextFields["editor.field.password"]
        XCTAssertTrue(passwordField.waitForExistence(timeout: Self.uiTimeout))
        XCTAssertTrue((passwordField.value as? String ?? "").contains("•"), "generated password not in the field")
        tap(app.buttons["editor.save"])

        // Saved: its detail is shown, then the row is in the list.
        XCTAssertTrue(app.staticTexts["item.title"].waitForExistence(timeout: Self.uiTimeout), "item not saved")
        // A signed build gets the system "Save Password?" sheet after an edited secure field
        // goes away: never save a vault secret in the system password manager.
        // Milestone 2 limit, gone in milestone 3 (OnePass becomes the AutoFill provider).
        let notNow = app.buttons.matching(NSPredicate(format: "label IN %@", ["Not Now", "Pas maintenant"])).firstMatch
        if notNow.waitForExistence(timeout: 3) { notNow.tap() }
        let search = tabButton(app, id: "tab.search", label: "Rechercher")
        tap(search)
        XCTAssertTrue(row(app).waitForExistence(timeout: Self.uiTimeout), "row missing after save")

        // Search: a query that matches nothing hides the row, then "atlas" finds it.
        // iOS 26 search tab: the field opens when the tab is chosen (tapped again if needed).
        let field = app.searchFields.firstMatch
        if !field.waitForExistence(timeout: 3) { search.tap() }
        tap(field)
        field.typeText("zzqx")
        XCTAssertTrue(app.staticTexts["search.empty"].waitForExistence(timeout: Self.uiTimeout), "no empty state")
        XCTAssertFalse(row(app).exists, "row shown for a query that does not match")
        let clear = field.buttons.firstMatch
        if clear.exists {
            clear.tap()
        } else {
            field.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: 4))
        }
        field.typeText("atlas")
        XCTAssertTrue(row(app).waitForExistence(timeout: Self.uiTimeout), "search did not find the item")
        XCTAssertFalse(app.staticTexts["search.empty"].exists)
        XCTAssertTrue((field.value as? String ?? "").localizedCaseInsensitiveContains("atlas"))

        // Leave the search (its close button brings the tab bar back).
        field.typeText("\n")
        let home = tabButton(app, id: "tab.home", label: "Accueil")
        for label in ["Fermer", "Annuler", "Close", "Cancel"] where !home.isHittable {
            let close = app.buttons[label].firstMatch
            if close.exists, close.isHittable { close.tap() }
        }

        // Lock from the account menu (on the Accueil tab).
        tap(home)
        let back = app.navigationBars.buttons.element(boundBy: 0)
        let menu = app.descendants(matching: .any)["account.menu"].firstMatch
        var pops = 0
        while !menu.waitForExistence(timeout: 2), back.exists, pops < 4 {
            back.tap()
            pops += 1
        }
        tap(menu)
        // Menu items keep their label in the accessibility tree, not always their identifier.
        let lockItem = app.descendants(matching: .any)["account.lock"].firstMatch
        tap(lockItem.waitForExistence(timeout: 2) ? lockItem : app.buttons["Verrouiller"].firstMatch)

        // Unlock with the master password (Argon2id again).
        type(Self.password, into: app.secureTextFields["lock.password"])
        tap(app.buttons["lock.unlock"])
        let unlocked = tabButton(app, id: "tab.home", label: "Accueil").waitForExistence(timeout: Self.kdfTimeout)
        if !unlocked, app.staticTexts["lock.error"].exists {
            XCTFail("unlock refused: \(app.staticTexts["lock.error"].label)")
        }
        XCTAssertTrue(unlocked, "not unlocked")

        // The row is still there.
        tap(tabButton(app, id: "tab.search", label: "Rechercher"))
        XCTAssertTrue(row(app).waitForExistence(timeout: Self.uiTimeout), "row missing after unlock")
    }

    // MARK: - Helpers

    private func row(_ app: XCUIApplication) -> XCUIElement {
        app.descendants(matching: .any)["list.row.\(Self.title)"].firstMatch
    }

    /// A tab of the iOS 26 tab bar, by identifier when the system keeps it, else by its label.
    private func tabButton(_ app: XCUIApplication, id: String, label: String) -> XCUIElement {
        let byID = app.buttons[id]
        if byID.waitForExistence(timeout: 2) { return byID }
        return app.tabBars.buttons[label].firstMatch
    }

    private func tap(_ element: XCUIElement, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(element.waitForExistence(timeout: Self.uiTimeout), "missing \(element)", file: file, line: line)
        let enabled = expectation(for: NSPredicate(format: "isEnabled == true"), evaluatedWith: element)
        wait(for: [enabled], timeout: Self.uiTimeout)
        // Under the keyboard or below the fold: scroll the form up a little at a time.
        var attempts = 0
        while !element.isHittable, attempts < 6 {
            let app = XCUIApplication()
            let from = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.7))
            from.press(forDuration: 0.05, thenDragTo: app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)))
            attempts += 1
        }
        if !element.isHittable { print("Screen when \(element) was not reachable:\n\(XCUIApplication().debugDescription)") }
        XCTAssertTrue(element.isHittable, "not reachable: \(element)", file: file, line: line)
        element.tap()
    }

    private func type(_ text: String, into element: XCUIElement, file: StaticString = #filePath, line: UInt = #line) {
        tap(element, file: file, line: line)
        // A tap that lands during a transition may not give the focus: tap again once.
        if !(element.value(forKey: "hasKeyboardFocus") as? Bool ?? true) { element.tap() }
        element.typeText(text)
    }
}
