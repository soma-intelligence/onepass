import XCTest

/// Open and sign in on iPhone, end to end (spec 2026-11-04-open-and-sign-in), on the agent's own
/// simulator after `SafariAutofillUITests/test1Prepare` (account, the "Atlas Cloud" Login of the local
/// test page with its one-time code, Face ID on, the Safari extension on for every website). In the
/// app, the Login's website is tapped; Safari opens the page and OnePass signs in by itself:
/// identifier, password, then the code, with no tap in Safari. The extension's vault is locked: Face ID
/// runs once (the runner posts the match), else the test fails. Fictional data only.
@MainActor
final class OpenAndSignInUITests: XCTestCase {
    private static let masterPassword = "ruisseau-tapis-orage-comète"
    private static let title = "Atlas Cloud"
    private static let kdfTimeout: TimeInterval = 90
    private static let uiTimeout: TimeInterval = 15

    private let onePass = XCUIApplication(bundleIdentifier: "me.somalabs.onepass")
    private let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
    private let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")

    override func setUp() async throws {
        continueAfterFailure = false
    }

    func test11OpenAndSignIn() throws {
        // A fresh Safari: no page of the site open from an earlier test.
        safari.terminate()
        openItem()
        Thread.sleep(forTimeInterval: 2)
        attachScreenshot("item")
        let link = onePass.buttons["item.url.open.0"]
        var swipes = 0
        while !(link.exists && link.isHittable), swipes < 5 {
            onePass.swipeUp()
            swipes += 1
        }
        XCTAssertTrue(link.waitForExistence(timeout: Self.uiTimeout), "no website row")
        Thread.sleep(forTimeInterval: 1.5)
        link.tap()

        XCTAssertTrue(safari.wait(for: .runningForeground, timeout: Self.uiTimeout), "Safari did not open")
        allowExtensionIfAsked()
        let welcome = safari.staticTexts.matching(NSPredicate(format: "label IN %@", ["Bienvenue"])).firstMatch
        // Safari's own "Save Password?" sheet can cover the end page: not ours, put away.
        let notNow = safari.buttons.matching(NSPredicate(format: "label IN %@", ["Not Now", "Plus tard", "Pas maintenant"])).firstMatch
        let deadline = Date().addingTimeInterval(75)
        var reached = false
        while Date() < deadline {
            if notNow.exists && notNow.isHittable { notNow.tap() }
            if welcome.exists && welcome.isHittable { reached = true; break }
            Thread.sleep(forTimeInterval: 0.5)
        }
        attachScreenshot(reached ? "signed-in" : "not-signed-in")
        if !reached { print("Safari when the sign-in stopped:\n\(safari.debugDescription)") }
        XCTAssertTrue(reached, "Open and sign in did not reach the signed-in page")
        Thread.sleep(forTimeInterval: 3)
    }

    /// The app unlocked (Face ID by itself, else the master password), the Login opened from search.
    private func openItem() {
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
        query.typeText(Self.title)
        let found = onePass.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", Self.title))
            .matching(NSPredicate(format: "elementType != %d", XCUIElement.ElementType.searchField.rawValue)).firstMatch
        XCTAssertTrue(found.waitForExistence(timeout: Self.uiTimeout), "the Login is not in the app")
        // The keyboard down, then the row.
        if onePass.keyboards.count > 0 { onePass.typeText("\n") }
        Thread.sleep(forTimeInterval: 0.5)
        found.tap()
        XCTAssertTrue(onePass.staticTexts["item.title"].waitForExistence(timeout: Self.uiTimeout), "item not opened")
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

    private func attachScreenshot(_ name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
