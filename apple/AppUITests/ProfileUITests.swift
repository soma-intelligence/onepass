import XCTest

/// Profil (spec 2026-11-14-profile-account-security) on iPhone, on the demo account: the account row
/// of the account panel opens it, it shows the Compte and Sécurité cards, and their rows open what
/// they say. Debug demo data only.
@MainActor
final class ProfileUITests: XCTestCase {
    /// The demo account derives a real Argon2id key: minutes on a busy Mac.
    private static let seedTimeout: TimeInterval = 600
    private static let uiTimeout: TimeInterval = 15

    private var app: XCUIApplication!

    override func setUp() async throws {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchArguments += [
            "-OnePassDemoData", "YES", "-OnePassDemoBiometrics", "NO", "-OnePassDemoCrypto", "NO",
        ]
        app.launch()
        XCTAssertTrue(element("account.menu").waitForExistence(timeout: Self.seedTimeout), "demo vault not shown")
    }

    private func element(_ id: String) -> XCUIElement {
        app.descendants(matching: .any)[id].firstMatch
    }

    /// Scrolls the Profil until `id` is on screen.
    private func reveal(_ id: String) -> XCUIElement {
        let target = element(id)
        var tries = 0
        while !(target.exists && target.isHittable), tries < 6 {
            app.swipeUp()
            tries += 1
        }
        return target
    }

    func testAccountRowOpensProfileWithAccountAndSecurity() throws {
        element("account.menu").tap()
        let row = element("account.current")
        XCTAssertTrue(row.waitForExistence(timeout: Self.uiTimeout), "account panel without its account row")
        row.tap()
        XCTAssertTrue(element("profile.account").waitForExistence(timeout: Self.uiTimeout), "Profil not opened")
        XCTAssertTrue(element("profile.deviceBadge").exists)
        XCTAssertTrue(element("profile.account.sync").exists)
        XCTAssertTrue(reveal("profile.security.watchtower").exists)
        XCTAssertTrue(reveal("profile.security.passkeys").exists)
    }

    func testSecurityRowsOpenTheirScreens() throws {
        element("account.menu").tap()
        element("account.current").tap()
        XCTAssertTrue(element("profile.account").waitForExistence(timeout: Self.uiTimeout))

        // Mot de passe principal: the change sheet.
        reveal("profile.security.password").tap()
        let current = element("settings.changePassword.current")
        XCTAssertTrue(current.waitForExistence(timeout: Self.uiTimeout), "change password sheet not shown")
        app.swipeDown(velocity: .fast)
        XCTAssertTrue(current.waitForNonExistence(timeout: Self.uiTimeout))

        // Déverrouillage: Réglages.
        reveal("profile.security.unlock").tap()
        let done = element("settings.done")
        XCTAssertTrue(done.waitForExistence(timeout: 90), "Réglages not opened")
        done.tap()
        XCTAssertTrue(done.waitForNonExistence(timeout: Self.uiTimeout))

        // Passkeys: the filtered list, pushed over the Profil.
        reveal("profile.security.passkeys").tap()
        XCTAssertTrue(element("profile.account").waitForNonExistence(timeout: Self.uiTimeout), "passkeys list not pushed")
    }
}
