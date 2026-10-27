import XCTest

/// AutoFill end-to-end on `OnePass M3 iPhone` against the `AutoFillHost` test app (ruling A16):
/// OnePass reset, account created, a Login saved, OnePass turned on as the AutoFill provider, a
/// second Login saved without the system "Save Password?" sheet (spec 7), then the Login filled
/// into the host app through the extension, unlocked with the master password.
/// Fictional data only (`exemple.fr`, Camille Durand, Projet Atlas).
@MainActor
final class AutoFillUITests: XCTestCase {
    private static let masterPassword = "ruisseau-tapis-orage-comète"
    private static let title = "Exemple Atlas"
    private static let username = "camille.durand@exemple.fr"
    private static let password = "Atlas-2026-test"
    private static let secondTitle = "Exemple Projet"
    private static let secondUsername = "c.durand@exemple.fr"
    private static let secondPassword = "Projet-2026-test"

    /// Account creation and unlock run Argon2id 256 MiB, in the extension too: the real cost.
    private static let kdfTimeout: TimeInterval = 90
    private static let uiTimeout: TimeInterval = 15

    private let onePass = XCUIApplication(bundleIdentifier: "me.somalabs.onepass")
    private let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    private let preferences = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
    /// The test target's own app: `AutoFillHost`.
    private let host = XCUIApplication()

    /// Debug: the app's own test store, defaults suite and keychain service
    /// (`me.somalabs.onepass.uitest`), never the real ones. The store is in the App Group container
    /// and the extension follows the isolated launch (`UITestIsolation`).
    private static let isolated = ["-OnePassTestIsolation", "YES"]

    override func setUp() async throws {
        continueAfterFailure = false
    }

    override func tearDown() async throws {
        // Empties the isolated store, defaults suite and keychain service.
        let cleanup = XCUIApplication(bundleIdentifier: "me.somalabs.onepass")
        cleanup.launchArguments += Self.isolated + ["-OnePassUITestReset", "YES"]
        cleanup.launch()
        cleanup.terminate()
    }

    func testFillLoginIntoHostApp() throws {
        turnOffInSystemSettings()
        // Debug only: starts from an empty isolated store, settings suite and keychain service.
        onePass.launchArguments += Self.isolated + ["-OnePassUITestReset", "YES"]
        onePass.launch()
        createAccount()

        // First Login, while OnePass is not the provider yet: the system sheet may still show up.
        addLogin(title: Self.title, username: Self.username, password: Self.password)
        let sheetBefore = saveSheet(timeout: 3)
        if let sheetBefore {
            print("Save Password sheet before activation: \(sheetBefore)")
            dismissSaveSheet()
        }

        // Réglages > Remplissage automatique > "Activer OnePass": the system alert, accepted.
        openAutoFillSettings()
        activateProvider()
        // The system settings show OnePass turned on (the proof that the provider is on).
        verifyOnInSystemSettings()
        onePass.activate()
        let status = onePass.descendants(matching: .any)["autofill.status"].firstMatch
        require(status, in: onePass, "autofill settings page after activation")
        if !waitForValue(status, "Activé", timeout: Self.uiTimeout) {
            // iOS 27.0 Simulator: `ASCredentialIdentityStore.state()` cannot reach
            // `com.apple.SafariFoundation.CredentialProviderExtensionHelper` (bootstrap look-up
            // fails, "No such process") and answers "off" while the system settings show OnePass on.
            // Kept visible in the log and the report; to check on a device, where "Activé" is expected.
            attachScreenshot("status-not-refreshed")
            print("Simulator limit: autofill.status is \(String(describing: status.value)) while the system settings show OnePass on")
        }
        // Back to the settings list, then to Accueil (Réglages is a tab on iPhone, a sheet with
        // "OK" elsewhere).
        let back = onePass.navigationBars["Remplissage automatique"].buttons.firstMatch
        if back.exists { tap(back, in: onePass) }
        let done = onePass.buttons["settings.done"]
        if done.exists {
            tap(done, in: onePass)
        } else {
            tap(tabButton(onePass, id: "tab.home", label: "Accueil"), in: onePass)
            // Accueil still shows the first Login: back to its root, where "Nouvel élément" is.
            let back = onePass.navigationBars.buttons.element(boundBy: 0)
            var pops = 0
            while !onePass.buttons["items.new"].waitForExistence(timeout: 2), back.exists, pops < 4 {
                back.tap()
                pops += 1
            }
        }

        // Second Login, OnePass now the provider: no "Save Password?" sheet (spec 7). Limit: an
        // absence is only watched for 10 s (the sheet came within 3 s before activation).
        addLogin(title: Self.secondTitle, username: Self.secondUsername, password: Self.secondPassword)
        if let sheet = saveSheet(timeout: 10) {
            attachScreenshot("save-sheet-after-activation")
            XCTFail("Save Password sheet shown with OnePass as the provider: \(sheet)")
        }

        // AutoFillHost: password field, then the AutoFill key above the keyboard.
        host.launch()
        let passwordField = host.secureTextFields["host.password"]
        tap(passwordField, in: host)
        openOnePassFromKeyboard()

        // The extension: master password (Argon2id in the extension process), then the Login.
        let master = element("autofill.password", type: .secureTextField)
        XCTAssertTrue(master.waitForExistence(timeout: Self.uiTimeout), "extension unlock screen missing")
        attachScreenshot("extension-unlock")
        master.tap()
        master.typeText(Self.masterPassword)
        element("autofill.unlock", type: .button).tap()
        // The host app has no associated domain (ruling A16): nothing "Pour ce site", the Login is
        // among "Autres éléments", unfolded by `autofill.others`.
        let candidate = host.descendants(matching: .any)["autofill.candidate.\(Self.title)"].firstMatch
        let others = host.buttons["autofill.others"]
        let listShown = XCTNSPredicateExpectation(
            predicate: NSPredicate { _, _ in candidate.exists || others.exists }, object: nil)
        if XCTWaiter().wait(for: [listShown], timeout: Self.kdfTimeout) != .completed {
            let error = element("autofill.error", type: .staticText)
            if error.exists { XCTFail("extension unlock refused: \(error.label)") }
            dump("extension after unlock")
            XCTFail("extension did not unlock")
            return
        }
        attachScreenshot("extension-list")
        if !candidate.exists {
            print("No Login for this app: \(others.label)")
            tap(others, in: host)
        }
        require(candidate, in: host, "candidate list")
        attachScreenshot("extension-list-others")
        tap(candidate, in: host)

        // Filled: the username in clear, the password masked but not empty.
        let usernameField = host.textFields["host.username"]
        XCTAssertTrue(waitForValue(usernameField, Self.username, timeout: Self.uiTimeout),
                      "username not filled: \(String(describing: usernameField.value))")
        let masked = passwordField.value as? String ?? ""
        XCTAssertFalse(masked.isEmpty || masked == "Mot de passe", "password not filled")
        // The host reports the length it received, never the password itself.
        tap(host.buttons["host.signIn"], in: host)
        let report = host.staticTexts["host.status"]
        XCTAssertTrue(report.waitForExistence(timeout: Self.uiTimeout))
        XCTAssertTrue(report.label.contains(Self.username), report.label)
        XCTAssertTrue(report.label.contains("mot de passe : \(Self.password.count) caractères"), report.label)
    }

    // MARK: - OnePass

    /// Same steps as `OnboardingAndItemUITests`.
    private func createAccount() {
        tap(onePass.buttons["onboarding.create"], in: onePass)
        tap(onePass.buttons["onboarding.primary"], in: onePass)
        type(Self.masterPassword, into: onePass.secureTextFields["onboarding.password"], in: onePass)
        type(Self.masterPassword, into: onePass.secureTextFields["onboarding.confirm"], in: onePass)
        tap(onePass.buttons["onboarding.primary"], in: onePass)
        let kitStored = onePass.buttons["onboarding.kitStored"]
        XCTAssertTrue(kitStored.waitForExistence(timeout: Self.kdfTimeout), "account not created")
        tap(kitStored, in: onePass)
        tap(onePass.buttons["onboarding.primary"], in: onePass)
        let later = onePass.buttons["onboarding.skip"]
        if later.waitForExistence(timeout: 3) { tap(later, in: onePass) }
        let open = onePass.buttons["onboarding.primary"]
        XCTAssertTrue(open.waitForExistence(timeout: Self.uiTimeout))
        tap(open, in: onePass)
    }

    private func addLogin(title: String, username: String, password: String) {
        tap(onePass.buttons["items.new"], in: onePass)
        tap(onePass.buttons["newItem.login"], in: onePass)
        type(title + "\n", into: onePass.textFields["editor.title"], in: onePass)
        type(username + "\n", into: onePass.textFields["editor.field.username"], in: onePass)
        type(password, into: onePass.secureTextFields["editor.field.password"], in: onePass)
        tap(onePass.buttons["editor.save"], in: onePass)
        XCTAssertTrue(onePass.staticTexts["item.title"].waitForExistence(timeout: Self.uiTimeout), "\(title) not saved")
    }

    private func openAutoFillSettings() {
        // iPhone: Réglages is a tab.
        tap(tabButton(onePass, id: "tab.settings", label: "Réglages"), in: onePass)
        // A tap that lands while the sheet is still sliding up does not push the page: tap again.
        let row = onePass.descendants(matching: .any)["settings.autofill"].firstMatch
        let status = onePass.descendants(matching: .any)["autofill.status"].firstMatch
        var taps = 0
        repeat {
            tap(row, in: onePass)
            taps += 1
        } while !status.waitForExistence(timeout: 3) && row.exists && taps < 3
    }

    /// "Activer OnePass", then the system alert accepted through Springboard. No alert when the
    /// provider is already on for the system (the request answers at once).
    private func activateProvider() {
        let status = onePass.descendants(matching: .any)["autofill.status"].firstMatch
        require(status, in: onePass, "autofill settings page")
        // Read once the page appears: empty while the state is read.
        _ = waitForValue(status, "Désactivé", timeout: Self.uiTimeout)
        // The provider was turned off first: "Activer OnePass" is shown and asks the system.
        tap(onePass.buttons["autofill.enable"], in: onePass)
        let accept = springboard.buttons
            .matching(Self.labelPredicate(["Turn On", "Activer", "Allow", "Autoriser"])).firstMatch
        guard accept.waitForExistence(timeout: 10) else {
            dump("springboard without the activation alert", springboard)
            attachScreenshot("no-activation-alert")
            XCTFail("no system alert after \"Activer OnePass\"")
            return
        }
        attachScreenshot("activation-alert")
        print("Activation alert: \(springboard.alerts.firstMatch.label), button \(accept.label)")
        accept.tap()
        XCTAssertTrue(accept.waitForNonExistence(timeout: Self.uiTimeout), "activation alert still shown")
    }

    /// Settings > General > AutoFill & Passwords: the alert turned the OnePass switch on. Only read,
    /// never flipped here.
    private func verifyOnInSystemSettings() {
        preferences.launch()
        let toggle = systemSwitch()
        XCTAssertTrue(waitForValue(toggle, "1", timeout: Self.uiTimeout),
                      "OnePass not on in the system settings after the alert: \(String(describing: toggle.value))")
        print("System settings: \(toggle.label) = \(String(describing: toggle.value))")
        attachScreenshot("system-autofill-settings")
    }

    /// The OnePass switch of Settings > General > AutoFill & Passwords (Settings may reopen there).
    private func systemSwitch() -> XCUIElement {
        let toggle = preferences.switches.matching(NSPredicate(format: "label CONTAINS 'OnePass'")).firstMatch
        if toggle.waitForExistence(timeout: 3) { return toggle }
        let general = preferences.descendants(matching: .any).matching(Self.labelPredicate(["General", "Général"])).firstMatch
        tap(general, in: preferences)
        let autofill = preferences.descendants(matching: .any)
            .matching(Self.labelPredicate(["AutoFill & Passwords", "Remplissage automatique et mots de passe"])).firstMatch
        tap(autofill, in: preferences)
        require(toggle, in: preferences, "system AutoFill settings")
        return toggle
    }

    /// A Settings switch reports the whole row as its frame: tap the switch itself, on the right.
    private func flip(_ toggle: XCUIElement) {
        toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap()
    }

    /// The provider survives a reinstall: turned off first, so "Activer OnePass" shows the alert.
    private func turnOffInSystemSettings() {
        preferences.launch()
        let toggle = systemSwitch()
        if toggle.value as? String == "1" {
            flip(toggle)
            print("OnePass turned off in the system settings before the test")
        }
        XCTAssertTrue(waitForValue(toggle, "0", timeout: Self.uiTimeout), "OnePass still on in the system settings")
        preferences.terminate()
    }

    // MARK: - System

    /// The "Save Password?" sheet: the system one (Not Now) or the extension's save screen.
    private func saveSheet(timeout: TimeInterval) -> String? {
        let deadline = Date().addingTimeInterval(timeout)
        let notNow = Self.labelPredicate(["Not Now", "Pas maintenant"])
        repeat {
            for app in [onePass, springboard] {
                let button = app.buttons.matching(notNow).firstMatch
                if button.exists { return "\(app == onePass ? "OnePass" : "Springboard"): \(button.label)" }
                if app.buttons["autofill.save"].exists { return "extension save screen" }
            }
            Thread.sleep(forTimeInterval: 0.5)
        } while Date() < deadline
        return nil
    }

    private func dismissSaveSheet() {
        let notNow = Self.labelPredicate(["Not Now", "Pas maintenant"])
        for app in [onePass, springboard] {
            let button = app.buttons.matching(notNow).firstMatch
            if button.exists { button.tap(); return }
        }
        let cancel = onePass.buttons["autofill.cancel"]
        if cancel.exists { cancel.tap() }
    }

    /// The AutoFill key of the QuickType bar ("Passwords", or the OnePass suggestion), then OnePass
    /// in the provider chooser when the system shows one.
    private func openOnePassFromKeyboard() {
        let labels = ["Passwords", "Mots de passe", "Password", "Mot de passe", "OnePass"]
        let predicate = NSPredicate(format: "label IN %@ OR label CONTAINS 'OnePass' OR identifier CONTAINS[c] 'password'", labels)
        _ = host.keyboards.firstMatch.waitForExistence(timeout: Self.uiTimeout)
        let deadline = Date().addingTimeInterval(Self.uiTimeout)
        var key: XCUIElement?
        repeat {
            for app in [host, springboard] {
                let candidates = app.descendants(matching: .any).matching(predicate).allElementsBoundByIndex
                key = candidates.first {
                    $0.isHittable && $0.identifier != "host.password" && $0.identifier != "breadcrumb"
                        && $0.elementType != .secureTextField
                }
                if key != nil { break }
            }
            if key == nil { Thread.sleep(forTimeInterval: 0.5) }
        } while key == nil && Date() < deadline
        guard let key else {
            dump("keyboard without an AutoFill key", host)
            dump("springboard with the keyboard", springboard)
            attachScreenshot("keyboard")
            XCTFail("no AutoFill key above the keyboard")
            return
        }
        print("AutoFill key: \(key)")
        key.tap()

        // A provider chooser (Passwords or OnePass) when several providers are on.
        if element("autofill.password", type: .secureTextField).waitForExistence(timeout: 3) { return }
        for app in [host, springboard] {
            let onePassChoice = app.descendants(matching: .any)
                .matching(NSPredicate(format: "label == 'OnePass' AND elementType != %d", XCUIElement.ElementType.secureTextField.rawValue))
                .firstMatch
            if onePassChoice.exists, onePassChoice.isHittable {
                print("Provider chooser: \(onePassChoice)")
                onePassChoice.tap()
                return
            }
        }
    }

    /// An element of the extension: its remote view is in the host's hierarchy; the extension's own
    /// process is tried too.
    private func element(_ id: String, type: XCUIElement.ElementType) -> XCUIElement {
        let inHost = host.descendants(matching: type)[id].firstMatch
        if inHost.exists { return inHost }
        let inExtension = XCUIApplication(bundleIdentifier: "me.somalabs.onepass.autofill").descendants(matching: type)[id].firstMatch
        if inExtension.exists { return inExtension }
        let inSpringboard = springboard.descendants(matching: type)[id].firstMatch
        if inSpringboard.exists { return inSpringboard }
        return inHost
    }

    // MARK: - Helpers

    private static func labelPredicate(_ labels: [String]) -> NSPredicate {
        NSPredicate(format: "label IN %@", labels)
    }

    private func waitForValue(_ element: XCUIElement, _ value: String, timeout: TimeInterval) -> Bool {
        let expectation = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == %@", value), object: element)
        return XCTWaiter().wait(for: [expectation], timeout: timeout) == .completed
    }

    private func tabButton(_ app: XCUIApplication, id: String, label: String) -> XCUIElement {
        let byID = app.buttons[id]
        if byID.waitForExistence(timeout: 2) { return byID }
        return app.tabBars.buttons[label].firstMatch
    }

    /// Waits for the element; when it is missing, prints the hierarchy and keeps a screenshot
    /// before failing (XCTest's own failure triage can hang on this Simulator).
    private func require(_ element: XCUIElement, in app: XCUIApplication, _ what: String,
                         timeout: TimeInterval = AutoFillUITests.uiTimeout, file: StaticString = #filePath, line: UInt = #line) {
        if element.waitForExistence(timeout: timeout) { return }
        dump(what, app)
        attachScreenshot(what)
        XCTFail("missing \(element) (\(what))", file: file, line: line)
    }

    private func dump(_ what: String, _ app: XCUIApplication? = nil) {
        print("Hierarchy (\(what)):\n\((app ?? host).debugDescription)")
    }

    private func attachScreenshot(_ name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func tap(_ element: XCUIElement, in app: XCUIApplication, file: StaticString = #filePath, line: UInt = #line) {
        if !element.waitForExistence(timeout: Self.uiTimeout) {
            print("Screen when \(element) was missing:\n\(app.debugDescription)")
            attachScreenshot("missing")
        }
        XCTAssertTrue(element.exists, "missing \(element)", file: file, line: line)
        let enabled = expectation(for: NSPredicate(format: "isEnabled == true"), evaluatedWith: element)
        wait(for: [enabled], timeout: Self.uiTimeout)
        // Under the keyboard or below the fold: scroll up a little at a time.
        var attempts = 0
        while !element.isHittable, attempts < 6 {
            let from = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.7))
            from.press(forDuration: 0.05, thenDragTo: app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)))
            attempts += 1
        }
        if element.isHittable {
            element.tap()
        } else {
            // iOS 27 can report a tab bar button behind its glass as not hittable: tap its center.
            print("\(element) not hittable, tapped at its center")
            element.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
        }
    }

    private func type(_ text: String, into element: XCUIElement, in app: XCUIApplication,
                      file: StaticString = #filePath, line: UInt = #line) {
        tap(element, in: app, file: file, line: line)
        if !(element.value(forKey: "hasKeyboardFocus") as? Bool ?? true) { element.tap() }
        element.typeText(text)
    }
}
