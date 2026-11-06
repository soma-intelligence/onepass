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
    /// `TEST_RUNNER_ONEPASS_TEST_PORT` on the xcodebuild line: another port when several
    /// simulators run the page at once (`safari-test-site.py` reads `ONEPASS_TEST_PORT`).
    private static let site = "https://localhost:" + (ProcessInfo.processInfo.environment["ONEPASS_TEST_PORT"] ?? "8443")
    private static let username = "camille.durand@exemple.fr"
    private static let password = "Atlas-2026-test"
    private static let otp = "otpauth://totp/Atlas:camille?secret=JBSWY3DPEHPK3PXP&issuer=Atlas"

    private static let kdfTimeout: TimeInterval = 90
    private static let uiTimeout: TimeInterval = 15

    private let onePass = XCUIApplication(bundleIdentifier: "me.somalabs.onepass")
    private let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
    private let preferences = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
    private let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    /// iOS 27 draws the keyboard and its suggestion bar in this process.
    private let inputUI = XCUIApplication(bundleIdentifier: "com.apple.InputUI")

    override func setUp() async throws {
        continueAfterFailure = false
    }

    // MARK: - Preparation

    func test1Prepare() throws {
        // OnePass turned on as the AutoFill provider first: the identities the app publishes
        // while it is off are dropped by the system store.
        enableAutoFillProvider()
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
        // The biometrics step: "Activer Face ID" is the primary button (the runner posts the match).
        let offerCard = onePass.descendants(matching: .any)["onboarding.biometricsOffer"].firstMatch
        if offerCard.waitForExistence(timeout: 5) {
            tap(onePass.buttons["onboarding.primary"], in: onePass)
            let on = onePass.descendants(matching: .any)["onboarding.biometricsOn"].firstMatch
            print("Face ID turned on in onboarding: \(on.waitForExistence(timeout: 20))")
        }
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

    /// Settings > General > AutoFill & Passwords: OnePass on (the switch flipped when off).
    private func enableAutoFillProvider() {
        preferences.launch()
        let any = preferences.descendants(matching: .any)
        let toggle = preferences.switches.matching(NSPredicate(format: "label CONTAINS 'OnePass'")).firstMatch
        if !toggle.waitForExistence(timeout: 3) {
            tap(any.matching(NSPredicate(format: "label IN %@", ["General", "Général"])).firstMatch, in: preferences)
            tap(any.matching(NSPredicate(format: "label IN %@",
                ["AutoFill & Passwords", "Remplissage automatique et mots de passe"])).firstMatch, in: preferences)
        }
        XCTAssertTrue(toggle.waitForExistence(timeout: Self.uiTimeout), "no OnePass switch in AutoFill & Passwords")
        if toggle.value as? String == "0" {
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap()
        }
        // iOS may ask which provider fills by default (or to confirm): accepted.
        for label in ["Use OnePass", "Utiliser OnePass", "OK", "Turn On", "Activer"] {
            let b = any.matching(NSPredicate(format: "label == %@ AND elementType == %d", label, XCUIElement.ElementType.button.rawValue)).firstMatch
            if b.waitForExistence(timeout: 1) { b.tap(); break }
        }
        let on = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == '1'"), object: toggle)
        XCTAssertEqual(XCTWaiter().wait(for: [on], timeout: Self.uiTimeout), .completed, "OnePass not on as the AutoFill provider")
        attachScreenshot("autofill-provider-on")
        print("AutoFill settings after:\n\(preferences.debugDescription)")
        preferences.terminate()
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

    /// The app unlocked once (Face ID, else the master password), then locked: it publishes the
    /// AutoFill identities on unlock, and they stay for the keyboard while OnePass is locked.
    func test2bPublishIdentities() throws {
        onePass.launch()
        let field = onePass.secureTextFields["lock.password"]
        let home = onePass.buttons["items.new"]
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline, !home.exists { Thread.sleep(forTimeInterval: 0.5) }
        if !home.exists, field.exists {
            field.tap()
            field.typeText(Self.masterPassword + "\n")
        }
        // Face ID offered after a password unlock: turned on (the runner posts the match).
        let offer = onePass.buttons["biometricOffer.enable"]
        if offer.waitForExistence(timeout: 5) { offer.tap() }
        XCTAssertTrue(home.waitForExistence(timeout: Self.kdfTimeout), "app not unlocked")
        Thread.sleep(forTimeInterval: 4)
        lockOnePass()
        Thread.sleep(forTimeInterval: 2)
        onePass.terminate()
    }

    // MARK: - Keyboard (QuickType) and save, vault locked

    /// The identifier page, vault locked: the QuickType suggestion published by OnePass, then our
    /// unlock screen (Face ID once by itself; the runner posts the match), then the fill.
    func test3KeyboardFillLocked() throws {
        openPage("/")
        let email = safari.webViews.textFields.firstMatch
        fillFromKeyboard(field: email, step: "identifier")
        XCTAssertTrue(waitValue(email, contains: Self.username), "identifier not filled from the keyboard")
        attachScreenshot("keyboard-filled")
    }

    /// The whole sign-in from the keyboard only: identifier, password, then the one-time code.
    func test6KeyboardMultiStep() throws {
        openPage("/")
        let email = safari.webViews.textFields.firstMatch
        fillFromKeyboard(field: email, step: "identifier")
        XCTAssertTrue(waitValue(email, contains: Self.username), "identifier not filled")
        submitPage(["Continuer"])
        let password = safari.webViews.secureTextFields.firstMatch
        XCTAssertTrue(password.waitForExistence(timeout: 20), "password page not reached")
        fillFromKeyboard(field: password, step: "password")
        submitPage(["Se connecter"])
        let code = safari.webViews.textFields.firstMatch
        XCTAssertTrue(code.waitForExistence(timeout: 20), "code page not reached")
        Thread.sleep(forTimeInterval: 1)
        // A code field has no "Passwords" key: iOS offers a code only as a published identity
        // (ASOneTimeCodeCredentialIdentity). The Simulator cannot publish one (no identity store):
        // there, the code comes from our icon in the field.
        code.tap()
        Thread.sleep(forTimeInterval: 2)
        if !keyboardOffersOnePass() {
            attachScreenshot("code-keyboard")
            fillFromInPageMenu(step: "code")
        } else {
            fillFromKeyboard(field: code, step: "code")
        }
        let welcome = safari.staticTexts["Bienvenue"]
        // OnePass sends the code step once filled; else the page's own button.
        if !welcome.waitForExistence(timeout: 3) {
            XCTAssertTrue(waitValue(code, matching: "^[0-9]{6}$"), "code not filled")
            submitPage(["Vérifier"])
        }
        dismissSystemSaveSheet()
        XCTAssertTrue(welcome.waitForExistence(timeout: 20), "sign-in did not reach the end page")
        attachScreenshot("multistep-done")
    }

    /// An account OnePass does not know, typed by hand: after the sign-in, our card offers Save.
    func test4SaveNewLogin() throws {
        // A new address each run: a login saved by an earlier run would only be "already in OnePass".
        let run = Int(Date().timeIntervalSince1970) % 100_000
        typeSignIn(username: "nouveau.compte.\(run)@exemple.fr", password: "Nouveau-2026-test")
        decideOnCard(["Save", "Enregistrer"], expect: ["Save login for", "Enregistrer le login pour"])
    }

    /// The known account with a new password, typed by hand: our card offers Update.
    func test5UpdatePassword() throws {
        // A new password each run, so there is always something to update.
        typeSignIn(username: Self.username, password: "Atlas-2026-\(Int(Date().timeIntervalSince1970) % 100_000)")
        // Unlocked, the card asks to update. Opened while locked it cannot know the login yet: it asks
        // to save, and Save updates the existing login once Face ID opened the vault.
        decideOnCard(
            ["Update", "Mettre à jour", "Save", "Enregistrer"],
            expect: ["Update password for", "Mettre à jour le mot de passe pour", "Save login for", "Enregistrer le login pour"],
            outcome: ["updated", "mis à jour"])
    }

    /// iOS 27's own "Save Password?" sheet, OnePass chosen: our provider unlocks, then saves.
    func test7SystemSaveSheet() throws {
        let run = Int(Date().timeIntervalSince1970) % 100_000
        typeSignIn(username: "systeme.\(run)@exemple.fr", password: "Systeme-2026-test")
        let onePass = safari.buttons["OnePass"]
        var found = false
        let deadline = Date().addingTimeInterval(30)
        while Date() < deadline, !found {
            for app in [safari, springboard] where app.buttons["OnePass"].exists && app.buttons["Not Now"].exists {
                found = true
                attachScreenshot("system-save-sheet")
                app.buttons["OnePass"].tap()
                break
            }
            if !found { Thread.sleep(forTimeInterval: 0.5) }
        }
        XCTAssertTrue(found, "no system save sheet offering OnePass")
        _ = onePass
        unlockProviderIfAsked(step: "system-save")
        let provider = XCUIApplication(bundleIdentifier: "me.somalabs.onepass.autofill")
        let save = [safari, springboard, provider].map { $0.descendants(matching: .any)["autofill.save"].firstMatch }
        let shown = Date().addingTimeInterval(20)
        var button: XCUIElement?
        while Date() < shown, button == nil {
            button = save.first { $0.exists && $0.isHittable }
            if button == nil { Thread.sleep(forTimeInterval: 0.5) }
        }
        attachScreenshot("system-save-view")
        guard let button else {
            print("No save view:\n\(safari.debugDescription)")
            XCTFail("our save screen did not show")
            return
        }
        button.tap()
        let gone = Date().addingTimeInterval(20)
        while Date() < gone, button.exists { Thread.sleep(forTimeInterval: 0.5) }
        attachScreenshot("system-save-done")
        XCTAssertFalse(button.exists, "the save screen did not close")
    }

    // MARK: - Proof recordings (one flow each)

    /// Unknown address and password typed by hand: our card, Save (Face ID), then the login in the app.
    func test8ProofSaveNewLogin() throws {
        let user = "inconnu.\(Int(Date().timeIntervalSince1970) % 100_000)@exemple.fr"
        typeSignIn(username: user, password: "Inconnu-2026-test")
        decideOnCard(["Save", "Enregistrer"], expect: ["Save login for", "Enregistrer le login pour"], outcome: ["saved", "enregistré"])
        showInApp(user)
    }

    /// A login saved on this site, then a sign-in with a changed password: the card offers Update.
    func test9ProofUpdateCard() throws {
        let user = "change.\(Int(Date().timeIntervalSince1970) % 100_000)@exemple.fr"
        typeSignIn(username: user, password: "Change-2026-avant")
        decideOnCard(["Save", "Enregistrer"], expect: ["Save login for", "Enregistrer le login pour"], outcome: ["saved", "enregistré"])
        // Same Safari, same site, a new password.
        typeSignIn(username: user, password: "Change-2026-apres", relaunch: false)
        decideOnCard(["Update", "Mettre à jour"], expect: ["Update password for", "Mettre à jour le mot de passe pour"], outcome: ["updated", "mis à jour"])
    }

    /// A refused sign-in (the form comes back with an error): no card at all.
    func test10ProofFailedLoginNoCard() throws {
        let user = "refuse.\(Int(Date().timeIntervalSince1970) % 100_000)@exemple.fr"
        typeSignIn(username: user, password: "Refuse-2026-test")
        XCTAssertTrue(safari.staticTexts["Mot de passe incorrect."].waitForExistence(timeout: 20), "the site did not refuse")
        let any = safari.webViews.descendants(matching: .any)
        let card = any.matching(NSPredicate(format: "label BEGINSWITH %@ OR label BEGINSWITH %@ OR label BEGINSWITH %@ OR label BEGINSWITH %@",
            "Save login for", "Enregistrer le login pour", "Update password for", "Mettre à jour le mot de passe pour")).firstMatch
        let until = Date().addingTimeInterval(12)
        while Date() < until {
            XCTAssertFalse(card.exists, "a OnePass card after a refused sign-in")
            Thread.sleep(forTimeInterval: 0.5)
        }
        attachScreenshot("refused-no-card")
    }

    // MARK: - Proofs 2026-11-04: save every time, signup, AutoFill in another app

    /// `https://<name>.localhost:<port>`: one site per name (*.localhost is loopback in the
    /// simulator; the certificate names each of them).
    private static func host(_ name: String) -> String {
        "https://\(name).localhost:" + (ProcessInfo.processInfo.environment["ONEPASS_TEST_PORT"] ?? "8443")
    }

    private static let saveQuestion = ["Save login for", "Enregistrer le login pour"]
    private static let updateQuestion = ["Update password for", "Mettre à jour le mot de passe pour"]

    /// Three sites OnePass never saw, each with an unknown account: the card each time, Save. Then a
    /// second unknown account on one of them (a new login, not an update), the first account there
    /// with a new password (Update), and on a fourth site "Not now" followed by another new account
    /// (the card again). The logins are then found in the app.
    func test11ProofSaveEveryTime() throws {
        let run = Int(Date().timeIntervalSince1970) % 100_000
        safari.launch()
        for site in ["atlas", "borealis", "cobalt"] {
            typeLogin(site, username: "\(site).\(run)@exemple.fr", password: "\(site.capitalized)-\(run)-un")
            decideOnCard(["Save", "Enregistrer"], expect: Self.saveQuestion, outcome: ["saved", "enregistré"])
        }
        // Same site, another account never seen: a new login.
        typeLogin("borealis", username: "autre.\(run)@exemple.fr", password: "Autre-\(run)-un")
        decideOnCard(["Save", "Enregistrer"], expect: Self.saveQuestion, outcome: ["saved", "enregistré"])
        // Same site, the first account with a new password: an update.
        typeLogin("borealis", username: "borealis.\(run)@exemple.fr", password: "Borealis-\(run)-deux")
        decideOnCard(["Update", "Mettre à jour"], expect: Self.updateQuestion, outcome: ["updated", "mis à jour"])
        // "Not now" on a site never silences the next new account there.
        typeLogin("dune", username: "dune.\(run)@exemple.fr", password: "Dune-\(run)-un")
        decideOnCard(["Not now", "Pas maintenant"], expect: Self.saveQuestion, outcome: [])
        typeLogin("dune", username: "dune2.\(run)@exemple.fr", password: "Dune-\(run)-deux")
        decideOnCard(["Save", "Enregistrer"], expect: Self.saveQuestion, outcome: ["saved", "enregistré"])
        showInApp("\(run)@exemple.fr")
    }

    /// Face ID on from Réglages > Sécurité when onboarding could not turn it on (the simulator was
    /// enrolled after it ran), then the vault locked again.
    func test12aEnableFaceID() throws {
        onePass.launchArguments += ["-OnePassDemoSettingsPage", "security"]
        onePass.launch()
        let home = onePass.buttons["items.new"]
        let field = onePass.secureTextFields["lock.password"]
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline, !home.exists { Thread.sleep(forTimeInterval: 0.5) }
        if !home.exists, field.exists {
            field.tap()
            field.typeText(Self.masterPassword + "\n")
        }
        XCTAssertTrue(home.waitForExistence(timeout: Self.kdfTimeout), "app not unlocked")
        tap(onePass.descendants(matching: .any)["account.menu"].firstMatch, in: onePass)
        tap(onePass.descendants(matching: .any)["account.settings"].firstMatch, in: onePass)
        let toggle = onePass.switches["settings.biometrics"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 30), "no Face ID switch")
        print("Face ID switch before: \(String(describing: toggle.value))")
        if toggle.value as? String == "0" {
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap()
            let pw = onePass.secureTextFields.firstMatch
            if pw.waitForExistence(timeout: 5) {
                pw.tap()
                pw.typeText(Self.masterPassword + "\n")
            }
        }
        let on = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == '1'"), object: toggle)
        let ok = XCTWaiter().wait(for: [on], timeout: Self.kdfTimeout) == .completed
        attachScreenshot("faceid-switch")
        if !ok { print("Settings:\n\(onePass.debugDescription)") }
        XCTAssertTrue(ok, "Face ID not turned on")
        onePass.terminate()
    }

    /// The demo identity (fictional) the signup fill takes its name and e-mail from.
    func test12PrepareIdentity() throws {
        onePass.launch()
        let home = onePass.buttons["items.new"]
        let field = onePass.secureTextFields["lock.password"]
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline, !home.exists { Thread.sleep(forTimeInterval: 0.5) }
        if !home.exists, field.exists {
            field.tap()
            field.typeText(Self.masterPassword + "\n")
        }
        XCTAssertTrue(home.waitForExistence(timeout: Self.kdfTimeout), "app not unlocked")
        tap(home, in: onePass)
        tap(onePass.buttons["newItem.identity"], in: onePass)
        type("Camille Durand\n", into: onePass.textFields["editor.title"], in: onePass)
        type("Camille\n", into: onePass.textFields["editor.field.first_name"], in: onePass)
        addIdentityField(["Last name", "Nom"], id: "last_name", value: "Durand")
        addIdentityField(["Email", "E-mail"], id: "email", value: "camille.durand@exemple.fr")
        attachScreenshot("identity-editor")
        tap(onePass.buttons["editor.save"], in: onePass)
        XCTAssertTrue(onePass.staticTexts["item.title"].waitForExistence(timeout: Self.uiTimeout), "identity not saved")
        lockOnePass()
        onePass.terminate()
    }

    /// A field of the identity shown on demand: typed in place if there, else "add more", searched.
    private func addIdentityField(_ labels: [String], id: String, value: String) {
        let field = onePass.textFields["editor.field.\(id)"]
        if !field.waitForExistence(timeout: 1) {
            var closes = 0
            while onePass.keyboards.count > 0, closes < 3 {
                onePass.swipeDown()
                closes += 1
            }
            let more = onePass.descendants(matching: .any)["editor.addField"].firstMatch
            var swipes = 0
            while !(more.exists && more.isHittable), swipes < 6 {
                onePass.swipeUp()
                swipes += 1
            }
            tap(more, in: onePass)
            let search = onePass.textFields["editor.addField.search"]
            if search.waitForExistence(timeout: 5) { search.typeText(labels[0]) }
            let row = onePass.buttons.matching(NSPredicate(format: "label IN %@", labels)).firstMatch
            if row.waitForExistence(timeout: 3) { row.tap() } else { print("Add field popover:\n\(onePass.debugDescription)") }
        }
        type(value + "\n", into: field, in: onePass)
    }

    /// A create-account page OnePass never saw: the OnePass menu creates the account (identity, a
    /// username handle the field's pattern accepts, and a generated password in both password
    /// fields), the form is sent by hand, the card shows the login saved, and the app has it.
    func test13ProofSignup() throws {
        safari.launch()
        safari.open(URL(string: Self.host("eden") + "/signup")!)
        let name = safari.webViews.textFields.firstMatch
        XCTAssertTrue(name.waitForExistence(timeout: 30), "signup page not loaded")
        Thread.sleep(forTimeInterval: 1.5)
        let pw = safari.webViews.secureTextFields.firstMatch
        pw.tap()
        dismissStrongPasswordOffer()
        Thread.sleep(forTimeInterval: 1)
        let row = safari.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@ OR label BEGINSWITH %@",
            "Create the account with a strong password", "Créer le compte avec un mot de passe fort")).firstMatch
        let icon = safari.descendants(matching: .any)
            .matching(NSPredicate(format: "label IN %@", ["Ouvrir le menu OnePass", "Open the OnePass menu"])).firstMatch
        if !row.waitForExistence(timeout: 3) {
            XCTAssertTrue(icon.waitForExistence(timeout: Self.uiTimeout), "no OnePass icon in the field")
            icon.tap()
        }
        let deadline = Date().addingTimeInterval(Self.kdfTimeout)
        var typed = false
        while Date() < deadline, !(row.exists && row.isHittable) {
            let master = safari.secureTextFields.matching(NSPredicate(format: "placeholderValue IN %@",
                ["Mot de passe principal", "Master password", "Mot de passe maître"])).firstMatch
            if !typed, master.exists, Date() > deadline.addingTimeInterval(-Self.kdfTimeout + 15) {
                master.tap()
                master.typeText(Self.masterPassword + "\n")
                typed = true
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        attachScreenshot("signup-menu")
        guard row.exists else {
            print("Safari without the signup row:\n\(safari.debugDescription)")
            XCTFail("no signup row in the OnePass menu")
            return
        }
        Thread.sleep(forTimeInterval: 1)
        row.tap()
        let confirm = safari.webViews.secureTextFields.element(boundBy: 1)
        let filled = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value != nil AND value != ''"), object: confirm)
        XCTAssertEqual(XCTWaiter().wait(for: [filled], timeout: 20), .completed, "confirmation not filled")
        Thread.sleep(forTimeInterval: 2)
        attachScreenshot("signup-filled")
        let email = safari.webViews.textFields.element(boundBy: 1)
        let address = (email.value as? String) ?? ""
        // The username field takes no '@' (pattern, maxlength 20): a handle made from the identity.
        let handle = (safari.webViews.textFields.element(boundBy: 2).value as? String) ?? ""
        print("Signup filled: name \(String(describing: name.value)), e-mail \(address), username \(handle)")
        XCTAssertTrue(address.contains("@"), "e-mail not filled")
        XCTAssertFalse(handle.isEmpty || handle.contains("@"), "username not a handle: \(handle)")
        submitPage(["Créer mon compte"])
        decideSavedCard()
        showInApp(handle)
    }

    /// MS-04: a shipping address and a card typed by hand on a site OnePass never saw: our card offers
    /// to save each (the card shows the last four digits only), Save, then the same card typed again
    /// by hand: the card shows (no oracle for the page) and Save says it is already in OnePass.
    func test15ProofAddressAndCard() throws {
        let run = Int(Date().timeIntervalSince1970) % 100_000
        safari.launch()
        safari.open(URL(string: Self.host("cobalt") + "/address")!)
        let first = safari.webViews.textFields.firstMatch
        XCTAssertTrue(first.waitForExistence(timeout: 30), "address page not loaded")
        Thread.sleep(forTimeInterval: 1)
        allowExtensionIfAsked()
        let values = ["Camille", "Durand \(run)", "\(run % 90 + 1) rue de la Paix", "", "75002", "Paris"]
        for (i, v) in values.enumerated() where !v.isEmpty {
            let field = safari.webViews.textFields.element(boundBy: i)
            field.tap()
            closeOnePassMenuIfShown()
            field.typeText(v)
        }
        submitPage(["Continuer vers le paiement"])
        decideOnCard(["Save", "Enregistrer"], expect: ["Save this address", "Enregistrer cette adresse"])

        // A test card number (Luhn valid, never a real card), typed by hand.
        let typeCard = {
            safari.open(URL(string: Self.host("cobalt") + "/card")!)
            let holder = safari.webViews.textFields.firstMatch
            XCTAssertTrue(holder.waitForExistence(timeout: 30), "card page not loaded")
            Thread.sleep(forTimeInterval: 1)
            for (i, v) in ["Camille Durand", "4111 1111 1111 1111", "04/\(29 + run % 5)", "123"].enumerated() {
                let field = safari.webViews.textFields.element(boundBy: i)
                field.tap()
                closeOnePassMenuIfShown()
                field.typeText(v)
            }
            submitPage(["Payer 12,00 €"])
        }
        typeCard()
        decideOnCard(["Save", "Enregistrer"], expect: ["Save this card", "Enregistrer cette carte"])
        typeCard()
        decideOnCard(["Save", "Enregistrer"], expect: ["Save this card", "Enregistrer cette carte"], outcome: ["Already in OnePass", "Déjà dans OnePass"])
    }

    /// The card that only says a login is saved (a generated signup password, already confirmed).
    private func decideSavedCard() {
        let any = safari.webViews.descendants(matching: .any)
        let saved = any.matching(NSPredicate(format: "label ENDSWITH %@ OR label ENDSWITH %@", " saved", " enregistré")).firstMatch
        let deadline = Date().addingTimeInterval(30)
        while Date() < deadline, !saved.exists {
            dismissSystemSaveSheet()
            Thread.sleep(forTimeInterval: 0.3)
        }
        attachScreenshot(saved.exists ? "signup-saved-card" : "signup-no-card")
        if !saved.exists { print("Safari without the saved card:\n\(safari.debugDescription)") }
        XCTAssertTrue(saved.exists, "no saved card after the signup")
        print("Card: \(saved.label)")
        Thread.sleep(forTimeInterval: 3)
    }

    /// AutoFill in an app that is not Safari (AutoFillHost): the keyboard's Passwords key, OnePass,
    /// Face ID, the account, both fields filled; then a new account typed by hand and iOS's own
    /// "Save Password?" offer, if the simulator shows it.
    func test14ProofOtherApp() throws {
        let host = XCUIApplication()
        host.launch()
        let user = host.textFields["host.username"]
        let password = host.secureTextFields["host.password"]
        XCTAssertTrue(user.waitForExistence(timeout: Self.uiTimeout), "host app not shown")
        Thread.sleep(forTimeInterval: 1.5)
        user.tap()
        _ = host.keyboards.firstMatch.waitForExistence(timeout: Self.uiTimeout)
        Thread.sleep(forTimeInterval: 2)
        attachScreenshot("host-keyboard")
        let keyLabels = ["Passwords", "Mots de passe", "Password", "Mot de passe"]
        var key: XCUIElement?
        for app in [host, springboard, inputUI] where key == nil {
            key = app.descendants(matching: .any).matching(NSPredicate(format: "label IN %@", keyLabels))
                .allElementsBoundByIndex.first { $0.isHittable && $0.elementType != .secureTextField && $0.elementType != .textField }
        }
        if let key {
            key.tap()
        } else {
            let keyboard = host.keyboards.firstMatch
            host.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: keyboard.frame.midX, dy: keyboard.frame.minY - 19)).tap()
        }
        Thread.sleep(forTimeInterval: 2)
        for app in [host, springboard] {
            let choice = app.descendants(matching: .any).matching(NSPredicate(format: "label == 'OnePass' OR label BEGINSWITH 'OnePass'"))
                .allElementsBoundByIndex.first { $0.isHittable && $0.elementType != .secureTextField }
            if let choice { choice.tap(); break }
        }
        unlockProviderIfAsked(step: "host")
        let provider = XCUIApplication(bundleIdentifier: "me.somalabs.onepass.autofill")
        let candidate = [host, springboard, provider].map { $0.descendants(matching: .any)["autofill.candidate.\(Self.title)"].firstMatch }
        let others = [host, springboard, provider].map { $0.buttons["autofill.others"] }
        var found: XCUIElement?
        let deadline = Date().addingTimeInterval(Self.kdfTimeout)
        while Date() < deadline, found == nil {
            found = candidate.first { $0.exists }
            if found == nil, let more = others.first(where: { $0.exists && $0.isHittable }) {
                attachScreenshot("host-list")
                more.tap()
            }
            if found == nil { Thread.sleep(forTimeInterval: 0.5) }
        }
        attachScreenshot("host-candidates")
        guard let found else {
            print("No candidate:\n\(host.debugDescription)")
            XCTFail("the OnePass list did not show \(Self.title)")
            return
        }
        Thread.sleep(forTimeInterval: 1)
        found.tap()
        let filled = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value CONTAINS %@", Self.username), object: user)
        XCTAssertEqual(XCTWaiter().wait(for: [filled], timeout: Self.uiTimeout), .completed, "username not filled")
        let masked = password.value as? String ?? ""
        XCTAssertFalse(masked.isEmpty || masked == "Mot de passe", "password not filled")
        Thread.sleep(forTimeInterval: 2)
        attachScreenshot("host-filled")
        host.buttons["host.signIn"].tap()
        let report = host.staticTexts["host.status"]
        XCTAssertTrue(report.waitForExistence(timeout: Self.uiTimeout))
        XCTAssertTrue(report.label.contains("mot de passe : \(Self.password.count) caractères"), report.label)
        Thread.sleep(forTimeInterval: 3)

        // A new account typed by hand: iOS's own "Save Password?" offer, OnePass chosen, if shown.
        host.terminate()
        host.launch()
        let run = Int(Date().timeIntervalSince1970) % 100_000
        XCTAssertTrue(user.waitForExistence(timeout: Self.uiTimeout))
        user.tap()
        user.typeText("app.\(run)@exemple.fr")
        password.tap()
        dismissStrongPasswordOfferIn(host)
        password.typeText("App-\(run)-test")
        host.buttons["host.signIn"].tap()
        var sheet = false
        let until = Date().addingTimeInterval(15)
        while Date() < until, !sheet {
            for app in [host, springboard] where app.buttons["OnePass"].exists {
                sheet = true
                attachScreenshot("host-system-save-sheet")
                Thread.sleep(forTimeInterval: 1.5)
                app.buttons["OnePass"].tap()
                break
            }
            if !sheet { Thread.sleep(forTimeInterval: 0.5) }
        }
        print("System save sheet in the host app: \(sheet)")
        guard sheet else {
            attachScreenshot("host-no-system-sheet")
            return
        }
        unlockProviderIfAsked(step: "host-save")
        let save = [host, springboard, provider].map { $0.descendants(matching: .any)["autofill.save"].firstMatch }
        var button: XCUIElement?
        let shown = Date().addingTimeInterval(20)
        while Date() < shown, button == nil {
            button = save.first { $0.exists && $0.isHittable }
            if button == nil { Thread.sleep(forTimeInterval: 0.5) }
        }
        attachScreenshot("host-save-view")
        guard let button else {
            XCTFail("our save screen did not show")
            return
        }
        Thread.sleep(forTimeInterval: 1.5)
        button.tap()
        Thread.sleep(forTimeInterval: 3)
        attachScreenshot("host-save-done")
    }

    private func dismissStrongPasswordOfferIn(_ app: XCUIApplication) {
        let other = app.buttons.matching(NSPredicate(format: "label IN %@", ["Other Options…", "Choose My Own Password", "Choisir mon mot de passe"])).firstMatch
        if other.waitForExistence(timeout: 1), other.isHittable { other.tap() }
    }

    /// `site`/login: e-mail and password typed by hand on one page, then sent.
    private func typeLogin(_ site: String, username: String, password: String) {
        safari.open(URL(string: Self.host(site) + "/login")!)
        let email = safari.webViews.textFields.firstMatch
        XCTAssertTrue(email.waitForExistence(timeout: 30), "\(site): login page not loaded")
        Thread.sleep(forTimeInterval: 1)
        allowExtensionIfAsked()
        email.tap()
        closeOnePassMenuIfShown()
        email.typeText(username)
        let field = safari.webViews.secureTextFields.firstMatch
        field.tap()
        closeOnePassMenuIfShown()
        field.typeText(password)
        dismissStrongPasswordOffer()
        submitPage(["Se connecter"])
    }

    /// The app, unlocked (Face ID by itself, else the master password), searched for `user`.
    private func showInApp(_ user: String) {
        onePass.launch()
        let home = onePass.buttons["items.new"]
        let field = onePass.secureTextFields["lock.password"]
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline, !home.exists { Thread.sleep(forTimeInterval: 0.5) }
        if !home.exists, field.exists {
            field.tap()
            field.typeText(Self.masterPassword + "\n")
        }
        XCTAssertTrue(home.waitForExistence(timeout: Self.kdfTimeout), "app not unlocked")
        let byID = onePass.buttons["tab.search"]
        let search = byID.exists ? byID : onePass.buttons["Rechercher"]
        XCTAssertTrue(search.waitForExistence(timeout: Self.uiTimeout), "no search tab")
        search.tap()
        let query = onePass.searchFields.firstMatch
        if !query.waitForExistence(timeout: 3) { search.tap() }
        XCTAssertTrue(query.waitForExistence(timeout: Self.uiTimeout), "no search field")
        query.tap()
        query.typeText(user)
        let found = onePass.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", user))
            .matching(NSPredicate(format: "elementType != %d", XCUIElement.ElementType.searchField.rawValue)).firstMatch
        let ok = found.waitForExistence(timeout: Self.uiTimeout)
        attachScreenshot(ok ? "app-item" : "app-no-item")
        if !ok { print("App without the item:\n\(onePass.debugDescription)") }
        XCTAssertTrue(ok, "the saved login is not in the app")
        Thread.sleep(forTimeInterval: 3)
    }

    private func openPage(_ path: String) {
        safari.launch()
        safari.open(URL(string: Self.site + path)!)
        XCTAssertTrue(safari.webViews.firstMatch.waitForExistence(timeout: 30), "test page not loaded")
        Thread.sleep(forTimeInterval: 1.5)
    }

    /// Focuses `field`, taps the OnePass suggestion of the keyboard bar, unlocks if asked.
    private func fillFromKeyboard(field: XCUIElement, step: String) {
        XCTAssertTrue(field.waitForExistence(timeout: 20), "\(step): no field")
        field.tap()
        _ = safari.keyboards.firstMatch.waitForExistence(timeout: Self.uiTimeout)
        Thread.sleep(forTimeInterval: 2)
        attachScreenshot("quicktype-\(step)")
        // The suggestion OnePass published (user name, or the code's label), never our in-page menu.
        let wanted = NSPredicate(format: "label CONTAINS[c] %@ OR label CONTAINS[c] %@ OR label CONTAINS[c] 'OnePass'",
                                 Self.username, Self.title)
        var suggestion: XCUIElement?
        let deadline = Date().addingTimeInterval(Self.uiTimeout)
        repeat {
            for app in [safari, springboard, inputUI] {
                let found = app.descendants(matching: .any).matching(wanted).allElementsBoundByIndex
                    .first { $0.isHittable && $0.frame.minY > 400 && $0.elementType != .textField && $0.elementType != .secureTextField && !$0.label.hasPrefix("Ouvrir") && !$0.label.hasPrefix("Open") && $0.label != "OnePass" }
                if let found { suggestion = found; break }
            }
            if suggestion == nil { Thread.sleep(forTimeInterval: 0.5) }
        } while suggestion == nil && Date() < deadline
        guard let suggestion else {
            // No OnePass identity in the bar (the iOS 27.0 Simulator cannot reach the system
            // identity store): the bar's "Passwords" key, then OnePass, then the account.
            print("Keyboard without a OnePass suggestion (\(step)):\n\(safari.keyboards.firstMatch.debugDescription)")
            attachScreenshot("no-suggestion-\(step)")
            fillFromPasswordsKey(step: step)
            return
        }
        print("QuickType suggestion (\(step)): \(suggestion.label)")
        suggestion.tap()
        unlockProviderIfAsked(step: step)
    }

    private func keyboardOffersOnePass() -> Bool {
        let wanted = NSPredicate(format: "label CONTAINS[c] %@ OR label CONTAINS[c] %@", Self.username, Self.title)
        return [safari, springboard, inputUI].contains { app in
            app.descendants(matching: .any).matching(wanted).allElementsBoundByIndex
                .contains { $0.isHittable && $0.frame.minY > 400 && $0.elementType != .textField }
        }
    }

    /// Our icon in the focused field, the unlock sheet if locked (Face ID once), then the account.
    private func fillFromInPageMenu(step: String) {
        let icon = safari.descendants(matching: .any)
            .matching(NSPredicate(format: "label IN %@", ["Ouvrir le menu OnePass", "Open the OnePass menu"])).firstMatch
        XCTAssertTrue(icon.waitForExistence(timeout: Self.uiTimeout), "\(step): no OnePass icon in the field")
        icon.tap()
        let row = safari.descendants(matching: .any)
            .matching(NSPredicate(format: "label CONTAINS %@ AND label CONTAINS %@", Self.title, Self.username)).firstMatch
        let filled = safari.webViews.textFields.firstMatch
        let deadline = Date().addingTimeInterval(Self.kdfTimeout)
        var typed = false
        // Filled, or filled and sent: OnePass submits the code step by itself.
        let welcome = safari.staticTexts["Bienvenue"]
        while Date() < deadline {
            if welcome.exists { return }
            if filled.exists, let v = filled.value as? String, v.range(of: "^[0-9]{6}$", options: .regularExpression) != nil { return }
            if row.exists, row.isHittable {
                // The menu ignores a tap in its first moments (anti-clickjacking): wait, tap,
                // and tap again only if nothing was filled.
                attachScreenshot("menu-\(step)")
                Thread.sleep(forTimeInterval: 1)
                row.tap()
                Thread.sleep(forTimeInterval: 2)
                continue
            }
            let pw = safari.secureTextFields.matching(NSPredicate(format: "placeholderValue IN %@",
                ["Mot de passe principal", "Master password", "Mot de passe maître"])).firstMatch
            if !typed, pw.exists, Date() > deadline.addingTimeInterval(-Self.kdfTimeout + 15) {
                print("Face ID did not open the sheet (\(step)): master password")
                pw.tap()
                pw.typeText(Self.masterPassword + "\n")
                typed = true
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        XCTFail("\(step): the OnePass menu did not fill")
    }

    /// The key of the keyboard bar, OnePass among the providers, our unlock, then the account.
    private func fillFromPasswordsKey(step: String) {
        let keyLabels = ["Passwords", "Mots de passe", "Password", "Mot de passe", "Codes", "Passwords and codes"]
        var key: XCUIElement?
        for app in [safari, springboard, inputUI] where key == nil {
            key = app.descendants(matching: .any)
                .matching(NSPredicate(format: "label IN %@", keyLabels))
                .allElementsBoundByIndex.first { $0.isHittable && $0.elementType != .secureTextField && $0.elementType != .textField }
        }
        if let key {
            print("Passwords key (\(step)): \(key.label)")
            key.tap()
        } else {
            // The bar is drawn out of process on iOS 27 (not in the tree): its key sits centered
            // just above the keyboard's letters.
            let keyboard = safari.keyboards.firstMatch
            XCTAssertTrue(keyboard.exists, "\(step): no keyboard")
            let y = keyboard.frame.minY - 19
            print("Passwords key (\(step)): tapped at the bar, y \(y)")
            safari.coordinate(withNormalizedOffset: .zero)
                .withOffset(CGVector(dx: keyboard.frame.midX, dy: y)).tap()
        }
        Thread.sleep(forTimeInterval: 2)
        attachScreenshot("passwords-key-\(step)")
        // A provider chooser when Passwords and OnePass are both on.
        for app in [safari, springboard] {
            let choice = app.descendants(matching: .any)
                .matching(NSPredicate(format: "label == 'OnePass' OR label BEGINSWITH 'OnePass'")).allElementsBoundByIndex
                .first { $0.isHittable && $0.elementType != .secureTextField }
            if let choice {
                print("Provider chooser (\(step)): \(choice)")
                choice.tap()
                break
            }
        }
        unlockProviderIfAsked(step: step)
        let id = "autofill.candidate.\(Self.title)"
        var candidate: XCUIElement?
        let deadline = Date().addingTimeInterval(Self.kdfTimeout)
        repeat {
            for app in [safari, springboard, XCUIApplication(bundleIdentifier: "me.somalabs.onepass.autofill")] {
                let el = app.descendants(matching: .any)[id].firstMatch
                if el.exists { candidate = el; break }
            }
            if candidate == nil { Thread.sleep(forTimeInterval: 0.5) }
        } while candidate == nil && Date() < deadline
        attachScreenshot("provider-list-\(step)")
        guard let candidate else {
            print("Safari without our list (\(step)):\n\(safari.debugDescription)")
            XCTFail("\(step): the OnePass list did not show \(Self.title)")
            return
        }
        // The list can still be settling: tapped again while it stays.
        Thread.sleep(forTimeInterval: 1)
        var taps = 0
        repeat {
            candidate.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
            taps += 1
            Thread.sleep(forTimeInterval: 1.5)
        } while candidate.exists && taps < 3
        print("Account picked (\(step)) after \(taps) tap(s), list gone: \(!candidate.exists)")
    }

    /// Our unlock screen in the AutoFill sheet: Face ID runs once by itself (the runner posts a
    /// match); without it, the master password.
    private func unlockProviderIfAsked(step: String) {
        func find(_ id: String) -> XCUIElement {
            for app in [safari, springboard, XCUIApplication(bundleIdentifier: "me.somalabs.onepass.autofill")] {
                let el = app.descendants(matching: .any)[id].firstMatch
                if el.exists { return el }
            }
            return safari.descendants(matching: .any)[id].firstMatch
        }
        let deadline = Date().addingTimeInterval(8)
        var sawUnlock = false
        while Date() < deadline {
            if find("autofill.password").exists || find("autofill.biometrics").exists { sawUnlock = true; break }
            Thread.sleep(forTimeInterval: 0.5)
        }
        print("Unlock screen shown (\(step)): \(sawUnlock)")
        guard sawUnlock else { return }
        attachScreenshot("provider-unlock-\(step)")
        // Face ID: one automatic attempt; the sheet goes away by itself once it succeeds.
        let gone = Date().addingTimeInterval(15)
        while Date() < gone, find("autofill.password").exists || find("autofill.biometrics").exists {
            Thread.sleep(forTimeInterval: 0.5)
        }
        let field = find("autofill.password")
        if field.exists {
            print("Face ID did not unlock (\(step)): master password")
            field.tap()
            field.typeText(Self.masterPassword + "\n")
            let after = Date().addingTimeInterval(Self.kdfTimeout)
            while Date() < after, find("autofill.password").exists { Thread.sleep(forTimeInterval: 0.5) }
        }
    }

    private func typeSignIn(username: String, password: String, relaunch: Bool = true) {
        if relaunch {
            openPage("/")
        } else {
            safari.open(URL(string: Self.site + "/")!)
            Thread.sleep(forTimeInterval: 1.5)
        }
        let email = safari.webViews.textFields.firstMatch
        XCTAssertTrue(email.waitForExistence(timeout: 20))
        email.tap()
        closeOnePassMenuIfShown()
        email.typeText(username)
        submitPage(["Continuer"])
        let field = safari.webViews.secureTextFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 20), "password page not reached")
        field.tap()
        closeOnePassMenuIfShown()
        field.typeText(password)
        dismissStrongPasswordOffer()
        submitPage(["Se connecter"])
    }

    /// Our in-page sheet can open on focus: put away, typing goes on in the page.
    private func closeOnePassMenuIfShown() {
        let cancel = safari.webViews.buttons.matching(NSPredicate(format: "label IN %@", ["Annuler", "Cancel", "Fermer", "Close"])).firstMatch
        if cancel.waitForExistence(timeout: 1.5), cancel.isHittable { cancel.tap() }
    }

    private func dismissStrongPasswordOffer() {
        let other = safari.buttons.matching(NSPredicate(format: "label IN %@", ["Other Options…", "Choose My Own Password", "Choisir mon mot de passe"])).firstMatch
        if other.waitForExistence(timeout: 1), other.isHittable { other.tap() }
    }

    private func submitPage(_ labels: [String]) {
        let button = safari.webViews.buttons.matching(NSPredicate(format: "label IN %@", labels)).firstMatch
        XCTAssertTrue(button.waitForExistence(timeout: 20), "no \(labels) button")
        // The keyboard can cover it: Return submits the form as well.
        if button.isHittable { button.tap() } else { safari.typeText("\n") }
        Thread.sleep(forTimeInterval: 1)
    }

    /// The card at the top of the page: its question, then `button`.
    /// Waits for our card asking one of `question`, taps one of `button`, expects one of `outcome`.
    private func decideOnCard(
        _ button: [String], expect question: [String],
        outcome: [String] = ["saved", "enregistré", "updated", "mis à jour"]
    ) {
        let any = safari.webViews.descendants(matching: .any)
        let asks = NSCompoundPredicate(orPredicateWithSubpredicates: question.map { NSPredicate(format: "label BEGINSWITH %@", $0) })
        let title = any.matching(asks).firstMatch
        let deadline = Date().addingTimeInterval(30)
        while Date() < deadline, !title.exists {
            dismissSystemSaveSheet()
            Thread.sleep(forTimeInterval: 0.5)
        }
        attachScreenshot("save-card")
        guard title.exists else {
            print("Safari without our card:\n\(safari.debugDescription)")
            XCTFail("no OnePass save card (\(question[0]))")
            return
        }
        print("Card: \(title.label)")
        // iOS's own "Save Password?" alert can come up over our card a moment later: put away
        // first, then a pause (the card ignores a tap right after it was covered: click guard).
        let quiet = Date().addingTimeInterval(3)
        while Date() < quiet {
            if safari.alerts.count > 0 || springboard.alerts.count > 0 {
                Thread.sleep(forTimeInterval: 1)
                dismissSystemSaveSheet()
                Thread.sleep(forTimeInterval: 0.5)
            }
            Thread.sleep(forTimeInterval: 0.3)
        }
        Thread.sleep(forTimeInterval: 1.5)
        let primary = any.matching(NSPredicate(format: "label IN %@ AND elementType == %d", button, XCUIElement.ElementType.button.rawValue)).firstMatch
        XCTAssertTrue(primary.waitForExistence(timeout: 5), "no \(button) on the card")
        primary.tap()
        if outcome.isEmpty {
            // Put away: the card leaves.
            let gone = Date().addingTimeInterval(10)
            while Date() < gone, title.exists { Thread.sleep(forTimeInterval: 0.3) }
            XCTAssertFalse(title.exists, "the card did not go away")
            Thread.sleep(forTimeInterval: 1)
            return
        }
        let done = any.matching(NSCompoundPredicate(orPredicateWithSubpredicates: outcome.map { NSPredicate(format: "label CONTAINS[c] %@", $0) })).firstMatch
        let ok = done.waitForExistence(timeout: 30)
        attachScreenshot(ok ? "card-done" : "card-not-done")
        if !ok { print("Card after the tap:\n\(safari.debugDescription)") }
        XCTAssertTrue(ok, "the card did not confirm")
        Thread.sleep(forTimeInterval: 2)
    }

    /// The system "Save Password?" offer, if iOS shows one: noted, then put away.
    private func dismissSystemSaveSheet() {
        for app in [safari, springboard] {
            let notNow = app.buttons.matching(NSPredicate(format: "label IN %@", ["Not Now", "Plus tard", "Pas maintenant"])).firstMatch
            if notNow.exists, notNow.isHittable {
                print("System save offer shown")
                attachScreenshot("system-save-offer")
                notNow.tap()
            }
        }
    }

    private func waitValue(_ el: XCUIElement, contains text: String) -> Bool {
        let e = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value CONTAINS %@", text), object: el)
        return XCTWaiter().wait(for: [e], timeout: Self.uiTimeout) == .completed
    }

    private func waitValue(_ el: XCUIElement, matching regex: String) -> Bool {
        let e = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value MATCHES %@", regex), object: el)
        return XCTWaiter().wait(for: [e], timeout: Self.uiTimeout) == .completed
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
