import XCTest

/// iOS must never offer to copy a vault secret into the system password manager ("Save Password?"),
/// whatever the AutoFill provider. Runs on `OnePass Fresh iPhone`, erased before each run
/// (`make -C apple uitest-fresh`), so OnePass is never the provider and nothing closes the request
/// for it. Every place where a typed secret leaves the screen is watched for 10 s: account creation,
/// a new Login saved with a typed password, a typed password dropped ("Annuler", "Abandonner"), the
/// Login edited with a generated password (and "Confirmer avant d'afficher" turned on), lock and
/// unlock, then the reprompt by master password.
/// Fictional data only (`exemple.fr`, Camille Durand, Projet Atlas).
@MainActor
final class NoSaveSheetUITests: XCTestCase {
    private static let password = "ruisseau-tapis-orage-comète"
    private static let title = "Exemple Atlas"
    private static let username = "camille.durand@exemple.fr"
    private static let loginPassword = "Atlas-pont-givre-73"

    /// Account creation and unlock run Argon2id 256 MiB: the real cost, never lowered for the test.
    private static let kdfTimeout: TimeInterval = 90
    private static let uiTimeout: TimeInterval = 15
    /// How long the system sheet is watched for after a secret field leaves the screen. On a
    /// signed build without the fix it fades in 1 to 4 s after the editor closes.
    private static let sheetWatch: TimeInterval = 10

    /// Debug: the app's own test store, defaults suite and keychain service, never the real ones.
    /// In French whatever the simulator's language: the steps look for French button labels.
    private static let isolated = ["-OnePassTestIsolation", "YES", "-AppleLanguages", "(fr)", "-AppleLocale", "fr_FR"]

    override func setUp() async throws {
        continueAfterFailure = false
    }

    override func tearDown() async throws {
        let cleanup = XCUIApplication()
        cleanup.launchArguments += Self.isolated + ["-OnePassUITestReset", "YES"]
        cleanup.launch()
        cleanup.terminate()
    }

    func testNoSystemSaveSheetAfterTypedSecrets() throws {
        let app = XCUIApplication()
        app.launchArguments += Self.isolated + ["-OnePassUITestReset", "YES"]
        app.launch()

        // Account creation: the master password and its confirmation leave the screen.
        createAccount(app)
        assertNoSaveSheet(app, after: "account creation")

        // New Login, password typed on the keyboard.
        tap(app.buttons["items.new"])
        tap(app.buttons["newItem.login"])
        type(Self.title + "\n", into: app.textFields["editor.title"])
        type(Self.username + "\n", into: app.textFields["editor.field.username"])
        type(Self.loginPassword, into: passwordField(app))
        tap(app.buttons["editor.save"])
        XCTAssertTrue(app.staticTexts["item.title"].waitForExistence(timeout: Self.uiTimeout), "item not saved")
        assertNoSaveSheet(app, after: "a new Login saved")

        // Edited, a password typed, then "Annuler" and "Abandonner": the draft is dropped.
        tap(app.buttons["item.edit"])
        type("Brouillon-abandonne-41", into: passwordField(app))
        tap(app.buttons["editor.cancel"])
        tap(app.buttons["Abandonner"].firstMatch)
        XCTAssertTrue(app.buttons["item.edit"].waitForExistence(timeout: Self.uiTimeout), "draft not dropped")
        assertNoSaveSheet(app, after: "a draft dropped")

        // The same Login edited: a generated password, and the reprompt turned on.
        tap(app.buttons["item.edit"])
        tap(app.buttons["editor.generate.password"])
        XCTAssertTrue(app.staticTexts["generator.value"].waitForExistence(timeout: Self.uiTimeout))
        tap(app.buttons["generator.use"])
        let reprompt = app.switches["editor.reprompt"]
        scrollDown(app, to: reprompt)
        XCTAssertTrue(reprompt.isHittable, "reprompt switch not reachable")
        // The switch element spans the row: its control is at the trailing edge.
        reprompt.coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap()
        let on = expectation(for: NSPredicate(format: "value == '1'"), evaluatedWith: reprompt)
        wait(for: [on], timeout: Self.uiTimeout)
        tap(app.buttons["editor.save"])
        XCTAssertTrue(app.buttons["item.edit"].waitForExistence(timeout: Self.uiTimeout), "edit not saved")
        assertNoSaveSheet(app, after: "a Login edited")

        // Lock, then unlock with the master password.
        lock(app)
        type(Self.password, into: secretField(app, "lock.password"))
        tap(app.buttons["lock.unlock"])
        XCTAssertTrue(
            tabButton(app, id: "tab.home", label: "Accueil").waitForExistence(timeout: Self.kdfTimeout), "not unlocked")
        assertNoSaveSheet(app, after: "unlock")

        // Reprompt: no biometrics on the simulator, so the detail asks the master password
        // (straight away, or after "Afficher").
        tap(tabButton(app, id: "tab.items", label: "Éléments"))
        // Éléments lists the vaults and categories first: the Logins category holds the row.
        tap(app.staticTexts["Connexions"].firstMatch)
        let show = app.buttons["item.reprompt.show"]
        let asked = app.descendants(matching: .any)["item.reprompt.password"].firstMatch
        // Each tab keeps its own list: the row on screen is the hittable one.
        for _ in 0..<3 where !show.exists && !asked.exists {
            let rows = app.descendants(matching: .any).matching(identifier: "list.row.\(Self.title)")
            XCTAssertTrue(rows.firstMatch.waitForExistence(timeout: Self.uiTimeout), "row missing after unlock")
            rows.allElementsBoundByIndex.first(where: \.isHittable)?.tap()
            _ = asked.waitForExistence(timeout: 3) || show.exists
        }
        if show.exists { tap(show) }
        type(Self.password, into: secretField(app, "item.reprompt.password"))
        tap(app.buttons["item.reprompt.confirm"])
        XCTAssertTrue(asked.waitForNonExistence(timeout: Self.kdfTimeout), "reprompt not confirmed")
        assertNoSaveSheet(app, after: "the reprompt")
        assertNoSheetSeen()
    }

    // MARK: - The system sheet

    /// Steps after which the system sheet showed up (the test goes on to map every step, then fails).
    private var sheetSteps: [String] = []

    /// Watches the app and SpringBoard for the system sheet for `sheetWatch` seconds. A sheet found
    /// is recorded (screenshot attached) and refused with "Not Now" so the next steps still run; the
    /// test fails at its end (`assertNoSheetSeen`).
    private func assertNoSaveSheet(_ app: XCUIApplication, after step: String) {
        guard let found = SaveSheetWatch.firstSighting(in: app, for: Self.sheetWatch) else {
            print("No save sheet after \(step) (\(Int(Self.sheetWatch)) s)")
            return
        }
        let shot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        shot.name = "save sheet after \(step)"
        shot.lifetime = .keepAlways
        add(shot)
        print("SAVE SHEET after \(step): \(found)")
        sheetSteps.append(step)
        SaveSheetWatch.refuse(in: app)
    }

    private func assertNoSheetSeen(file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(
            sheetSteps.isEmpty, "system \"Save Password?\" sheet after: \(sheetSteps.joined(separator: ", "))",
            file: file, line: line)
    }

    // MARK: - Steps

    private func createAccount(_ app: XCUIApplication) {
        tap(app.buttons["onboarding.create"])
        tap(app.buttons["onboarding.primary"])
        // Return moves to the confirmation (905c8d41): with the keyboard up the confirmation sits
        // below the fold, and a drag from 70 % of the screen lands on the keyboard, not the form.
        type(Self.password + "\n", into: secretField(app, "onboarding.password"))
        let confirm = secretField(app, "onboarding.confirm")
        if !(confirm.value(forKey: "hasKeyboardFocus") as? Bool ?? false) { tap(confirm) }
        confirm.typeText(Self.password)
        tap(app.buttons["onboarding.primary"])
        let kitStored = app.buttons["onboarding.kitStored"]
        XCTAssertTrue(kitStored.waitForExistence(timeout: Self.kdfTimeout), "account not created")
        tap(kitStored)
        tap(app.buttons["onboarding.primary"])
        let later = app.buttons["onboarding.skip"]
        if later.waitForExistence(timeout: 3) { tap(later) }
        let open = app.buttons["onboarding.primary"]
        XCTAssertTrue(open.waitForExistence(timeout: Self.uiTimeout))
        tap(open)
        XCTAssertTrue(app.buttons["items.new"].waitForExistence(timeout: Self.uiTimeout), "app not opened")
    }

    private func lock(_ app: XCUIApplication) {
        tap(tabButton(app, id: "tab.home", label: "Accueil"))
        let back = app.navigationBars.buttons.element(boundBy: 0)
        let menu = app.descendants(matching: .any)["account.menu"].firstMatch
        var pops = 0
        while !menu.waitForExistence(timeout: 2), back.exists, pops < 4 {
            back.tap()
            pops += 1
        }
        tap(menu)
        let lockItem = app.descendants(matching: .any)["account.lock"].firstMatch
        tap(lockItem.waitForExistence(timeout: 2) ? lockItem : app.buttons["Verrouiller"].firstMatch)
    }

    // MARK: - Helpers

    /// A masked field by identifier, whatever its element type (secure or plain text field).
    private func secretField(_ app: XCUIApplication, _ id: String) -> XCUIElement {
        let secure = app.secureTextFields[id]
        if secure.waitForExistence(timeout: Self.uiTimeout) { return secure }
        return app.textFields[id]
    }

    private func passwordField(_ app: XCUIApplication) -> XCUIElement {
        secretField(app, "editor.field.password")
    }

    /// Swipes the form up until the element is on screen (a lazy form only builds the rows on
    /// screen, and a row already built may still sit below the fold).
    private func scrollDown(_ app: XCUIApplication, to element: XCUIElement) {
        var swipes = 0
        while !(element.exists && element.isHittable), swipes < 8 {
            app.swipeUp()
            swipes += 1
        }
    }

    private func tabButton(_ app: XCUIApplication, id: String, label: String) -> XCUIElement {
        let byID = app.buttons[id]
        if byID.waitForExistence(timeout: 2) { return byID }
        return app.tabBars.buttons[label].firstMatch
    }

    private func tap(_ element: XCUIElement, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(element.waitForExistence(timeout: Self.uiTimeout), "missing \(element)", file: file, line: line)
        let enabled = expectation(for: NSPredicate(format: "isEnabled == true"), evaluatedWith: element)
        wait(for: [enabled], timeout: Self.uiTimeout)
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
        if !(element.value(forKey: "hasKeyboardFocus") as? Bool ?? true) { element.tap() }
        element.typeText(text)
    }
}
