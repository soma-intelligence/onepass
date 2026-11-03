import XCTest

/// Safari autofill on iPhone, end to end (spec 2026-11-03-ios-safari-autofill), on the agent's own
/// simulator. `test1Prepare`: a OnePass account and a Login for the local test page, Face ID turned
/// on, the vault locked, the Safari extension turned on for every website. `test2SafariFlow`: the
/// local sign-in page (identifier, then password, then code) filled from the page, the vault
/// unlocked from the unlock sheet. The page is served at https://localhost:8443 by the test's own
/// script, with its root certificate added to the simulator. Fictional data only.
///
/// Face ID: the runner enrols the simulator and posts a match while the flow runs (notifyutil on the
/// host); without it the sheet falls back to the master password, typed here.
@MainActor
final class SafariAutofillUITests: XCTestCase {
    private static let masterPassword = "ruisseau-tapis-orage-comète"
    private static let title = "Atlas Cloud"
    private static let site = "https://localhost:8443"
    private static let username = "camille.durand@exemple.fr"
    private static let password = "Atlas-2026-test"
    private static let otp = "otpauth://totp/Atlas:camille?secret=JBSWY3DPEHPK3PXP&issuer=Atlas"

    private static let kdfTimeout: TimeInterval = 90
    private static let uiTimeout: TimeInterval = 15

    private let onePass = XCUIApplication(bundleIdentifier: "me.somalabs.onepass")
    private let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
    private let preferences = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
    private let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")

    override func setUp() async throws {
        continueAfterFailure = false
    }

    // MARK: - Preparation

    func test1Prepare() throws {
        onePass.launch()
        if onePass.buttons["onboarding.create"].waitForExistence(timeout: 10) {
            createAccount()
            addLogin()
        }
        let offer = onePass.buttons["biometricOffer.enable"]
        if offer.waitForExistence(timeout: 3) { offer.tap() }
        lockOnePass()
        onePass.terminate()
        enableSafariExtension()
    }

    private func createAccount() {
        tap(onePass.buttons["onboarding.create"], in: onePass)
        tap(onePass.buttons["onboarding.primary"], in: onePass)
        type(Self.masterPassword, into: onePass.secureTextFields["onboarding.password"], in: onePass)
        type(Self.masterPassword, into: onePass.secureTextFields["onboarding.confirm"], in: onePass)
        tap(onePass.buttons["onboarding.primary"], in: onePass)
        let kitStored = onePass.buttons["onboarding.kitStored"]
        XCTAssertTrue(kitStored.waitForExistence(timeout: Self.kdfTimeout), "account not created")
        // The box: tapped again until "Continue" turns on.
        let next = onePass.buttons["onboarding.primary"]
        var taps = 0
        repeat {
            tap(kitStored, in: onePass)
            taps += 1
        } while !waitEnabled(next, 3) && taps < 4
        tap(next, in: onePass)
        // Face ID offered during onboarding: turned on (the simulator is enrolled by the runner).
        let enable = onePass.buttons.matching(NSPredicate(format: "identifier CONTAINS[c] 'biometric' AND identifier CONTAINS[c] 'enable'")).firstMatch
        if enable.waitForExistence(timeout: 3) { enable.tap() }
        let later = onePass.buttons["onboarding.skip"]
        if later.waitForExistence(timeout: 3) { tap(later, in: onePass) }
        let open = onePass.buttons["onboarding.primary"]
        if open.waitForExistence(timeout: Self.uiTimeout) { tap(open, in: onePass) }
    }

    private func addLogin() {
        tap(onePass.buttons["items.new"], in: onePass)
        tap(onePass.buttons["newItem.login"], in: onePass)
        type(Self.title + "\n", into: onePass.textFields["editor.title"], in: onePass)
        type(Self.username + "\n", into: onePass.textFields["editor.field.username"], in: onePass)
        type(Self.password, into: onePass.secureTextFields["editor.field.password"], in: onePass)
        // The keyboard covers the rows below: closed first (Return, then a drag down).
        var closes = 0
        while onePass.keyboards.count > 0, closes < 4 {
            if closes == 0 { onePass.typeText("\n") } else { onePass.swipeDown() }
            closes += 1
            Thread.sleep(forTimeInterval: 0.5)
        }
        print("Keyboard after closing: \(onePass.keyboards.count)")
        // The website, below the fold (lazy rows): scrolled to, then added.
        let add = onePass.buttons["editor.addURL"]
        var swipes = 0
        while !(add.exists && add.isHittable), swipes < 5 {
            onePass.swipeUp()
            swipes += 1
        }
        // The first tap can only close the keyboard: again until the row is there.
        let url = onePass.textFields["editor.url.0"]
        var adds = 0
        repeat {
            tap(add, in: onePass)
            adds += 1
        } while !url.waitForExistence(timeout: 3) && adds < 4
        type(Self.site, into: url, in: onePass)
        // The one-time code: "add more", the template's code field.
        let more = onePass.descendants(matching: .any)["editor.addField"].firstMatch
        if more.waitForExistence(timeout: 3) {
            tap(more, in: onePass)
            let search = onePass.textFields["editor.addField.search"]
            if search.waitForExistence(timeout: 5) {
                search.typeText("totp")
                let row = onePass.buttons.matching(NSPredicate(format: "label CONTAINS[c] 'TOTP'")).firstMatch
                if row.waitForExistence(timeout: 3) { row.tap() } else { print("Add field popover:\n\(onePass.debugDescription)") }
            }
            let totp = onePass.descendants(matching: .any)["editor.field.totp"].firstMatch
            if totp.waitForExistence(timeout: 3) { type(Self.otp, into: totp, in: onePass) }
        }
        attachScreenshot("editor")
        tap(onePass.buttons["editor.save"], in: onePass)
        XCTAssertTrue(onePass.staticTexts["item.title"].waitForExistence(timeout: Self.uiTimeout), "Login not saved")
    }

    private func lockOnePass() {
        let lock = onePass.descendants(matching: .any)["account.lock"].firstMatch
        if lock.waitForExistence(timeout: 3), lock.isHittable {
            lock.tap()
            return
        }
        let menu = onePass.descendants(matching: .any)["account.menu"].firstMatch
        let pop = onePass.navigationBars.buttons.element(boundBy: 0)
        var pops = 0
        while !(menu.waitForExistence(timeout: 2) && menu.isHittable), pop.exists, pops < 4 {
            pop.tap()
            pops += 1
        }
        if menu.exists { tap(menu, in: onePass) }
        let byLabel = onePass.descendants(matching: .any)
            .matching(NSPredicate(format: "identifier == 'account.lock' OR label IN %@", ["Verrouiller", "Lock"])).firstMatch
        if byLabel.waitForExistence(timeout: 5) { byLabel.tap() }
    }

    /// Settings > Apps > Safari > Extensions > OnePass: on, and allowed on every website.
    private func enableSafariExtension() {
        preferences.launch()
        let any = preferences.descendants(matching: .any)
        func open(_ labels: [String]) {
            let el = any.matching(NSPredicate(format: "label IN %@", labels)).firstMatch
            if !el.waitForExistence(timeout: 5) {
                // Long lists: scroll a little and try again.
                for _ in 0..<6 where !el.isHittable { preferences.swipeUp() }
            }
            tap(el, in: preferences)
        }
        open(["Apps", "Applications", "Apps"])
        open(["Safari"])
        open(["Extensions"])
        open(["OnePass"])
        let toggle = preferences.switches.firstMatch
        if toggle.waitForExistence(timeout: 5), toggle.value as? String == "0" {
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap()
        }
        attachScreenshot("extension-on")
        let all = any.matching(NSPredicate(format: "label IN %@", ["All Websites", "Tous les sites web"])).firstMatch
        if all.waitForExistence(timeout: 5) {
            all.tap()
            let allow = any.matching(NSPredicate(format: "label IN %@", ["Allow", "Autoriser"])).firstMatch
            if allow.waitForExistence(timeout: 5) { allow.tap() }
        }
        attachScreenshot("extension-allowed")
        print("Settings after:\n\(preferences.debugDescription)")
        preferences.terminate()
    }

    // MARK: - Safari

    func test2SafariFlow() throws {
        safari.launch()
        safari.open(URL(string: Self.site + "/")!)
        let email = safari.webViews.textFields.firstMatch
        XCTAssertTrue(email.waitForExistence(timeout: 30), "test page not loaded")
        Thread.sleep(forTimeInterval: 1.5)
        email.tap()
        // Safari may ask once to allow the extension on this site.
        allowExtensionIfAsked()
        Thread.sleep(forTimeInterval: 1.5)
        attachScreenshot("icon-and-label")

        let icon = safari.descendants(matching: .any)
            .matching(NSPredicate(format: "label IN %@", ["Ouvrir le menu OnePass", "Open the OnePass menu"])).firstMatch
        if !icon.waitForExistence(timeout: Self.uiTimeout) {
            print("Safari without the OnePass icon:\n\(safari.debugDescription)")
            attachScreenshot("no-icon")
            XCTFail("no OnePass icon in the field")
            return
        }
        icon.tap()

        // The unlock sheet: Face ID runs once by itself; the runner posts the match. Else the password.
        // The menu row names the title and the account; the page heading names the title only.
        let row = safari.descendants(matching: .any)
            .matching(NSPredicate(format: "label CONTAINS %@ AND label CONTAINS %@", Self.title, Self.username)).firstMatch
        let passwordField = safari.secureTextFields.matching(NSPredicate(format: "placeholderValue IN %@ OR label IN %@",
            ["Mot de passe principal", "Master password"], ["Mot de passe principal", "Master password"])).firstMatch
        Thread.sleep(forTimeInterval: 2)
        attachScreenshot("unlock-sheet")
        if !row.waitForExistence(timeout: 12) {
            if passwordField.exists {
                print("Face ID did not open the vault: master password")
                passwordField.tap()
                passwordField.typeText(Self.masterPassword + "\n")
            }
        }
        if !row.waitForExistence(timeout: Self.kdfTimeout) {
            print("Safari after unlock:\n\(safari.debugDescription)")
            attachScreenshot("no-list")
            XCTFail("the menu did not list the Login after the unlock")
            return
        }
        Thread.sleep(forTimeInterval: 1)
        attachScreenshot("account-pick")
        row.tap()

        // The sign-in runs page after page: identifier, password, then the code.
        let welcome = safari.staticTexts.matching(NSPredicate(format: "label IN %@", ["Bienvenue"])).firstMatch
        // Safari's own "Save Password?" sheet can cover the end page: not ours, put it away.
        let notNow = safari.buttons.matching(NSPredicate(format: "label IN %@", ["Not Now", "Plus tard", "Pas maintenant"])).firstMatch
        let deadline = Date().addingTimeInterval(60)
        var reached = false
        while Date() < deadline {
            if notNow.exists && notNow.isHittable { notNow.tap() }
            if welcome.exists && welcome.isHittable { reached = true; break }
            Thread.sleep(forTimeInterval: 0.5)
        }
        if !reached { reached = welcome.exists }
        attachScreenshot(reached ? "signed-in" : "chain-stopped")
        if !reached {
            print("Safari when the chain stopped:\n\(safari.debugDescription)")
            XCTFail("the sign-in did not reach the end page")
        }
        Thread.sleep(forTimeInterval: 2)

        // QuickType: back to the first page, the field focused, the suggestion bar shown.
        safari.open(URL(string: Self.site + "/")!)
        let again = safari.webViews.textFields.firstMatch
        if again.waitForExistence(timeout: 20) {
            Thread.sleep(forTimeInterval: 1)
            again.tap()
            Thread.sleep(forTimeInterval: 3)
            attachScreenshot("quicktype")
            // Only the keyboard's bar counts (the OnePass menu row names the account too).
            let suggestion = safari.keyboards.descendants(matching: .any)
                .matching(NSPredicate(format: "label CONTAINS %@ OR label CONTAINS %@", Self.username, Self.title)).firstMatch
            print("QuickType suggestion shown: \(suggestion.exists)")
        }
    }

    private func allowExtensionIfAsked() {
        for app in [safari, springboard] {
            let allow = app.buttons.matching(NSPredicate(format: "label IN %@",
                ["Always Allow on Every Website", "Toujours autoriser sur tous les sites web", "Always Allow", "Toujours autoriser", "Allow for One Day"])).firstMatch
            if allow.waitForExistence(timeout: 2) {
                allow.tap()
                return
            }
        }
    }

    // MARK: - Helpers

    private func waitEnabled(_ element: XCUIElement, _ timeout: TimeInterval) -> Bool {
        let e = XCTNSPredicateExpectation(predicate: NSPredicate(format: "isEnabled == true"), object: element)
        return XCTWaiter().wait(for: [e], timeout: timeout) == .completed
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
        _ = waitEnabled(element, Self.uiTimeout)
        var attempts = 0
        while !element.isHittable, attempts < 6 {
            // Above the keyboard: a drag that starts on it would not scroll.
            let from = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.45))
            from.press(forDuration: 0.05, thenDragTo: app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.25)))
            attempts += 1
        }
        if element.isHittable {
            element.tap()
        } else {
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
