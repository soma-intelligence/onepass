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
        // The second-account test launches with its own arguments.
        if name.contains("SecondAccount") { return }
        launch()
    }

    private func launch(_ extra: [String] = []) {
        app = XCUIApplication()
        app.launchArguments += [
            "-OnePassDemoData", "YES", "-OnePassDemoBiometrics", "NO", "-OnePassDemoCrypto", "NO",
        ] + extra
        app.launch()
        XCTAssertTrue(element("account.menu").waitForExistence(timeout: Self.seedTimeout), "demo vault not shown")
    }

    /// iPhone: the account panel's account row opens the Profil.
    private func openProfile() {
        element("account.menu").tap()
        element("account.current").tap()
        XCTAssertTrue(element("profile.account").waitForExistence(timeout: Self.uiTimeout), "Profil not opened")
    }

    private func closeSettings() {
        let done = element("settings.done")
        XCTAssertTrue(done.waitForExistence(timeout: Self.uiTimeout))
        done.tap()
        XCTAssertTrue(done.waitForNonExistence(timeout: Self.uiTimeout))
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

    /// Synchronisation and Mode d'appareil open Réglages on their page, the device mode in view.
    func testSyncAndDeviceRowsOpenTheirSettingsPage() throws {
        try XCTSkipIf(UIDevice.current.userInterfaceIdiom == .pad, "iPhone only")
        openProfile()
        element("profile.account.sync").tap()
        XCTAssertTrue(element("settings.syncNow").waitForExistence(timeout: 90), "Sync page not opened")
        closeSettings()

        reveal("profile.security.device").tap()
        let picker = element("settings.deviceMode")
        XCTAssertTrue(picker.waitForExistence(timeout: 90), "Security page not opened")
        let shown = NSPredicate(format: "isHittable == true")
        expectation(for: shown, evaluatedWith: picker)
        waitForExpectations(timeout: Self.uiTimeout)
        closeSettings()
    }

    /// Watchtower switches to its tab; the ID row says it was copied.
    func testWatchtowerRowAndIDCopy() throws {
        try XCTSkipIf(UIDevice.current.userInterfaceIdiom == .pad, "iPhone only")
        openProfile()
        let id = element("profile.account.id")
        XCTAssertTrue(id.exists)
        let before = id.label
        id.tap()
        let changed = NSPredicate(format: "label != %@", before)
        expectation(for: changed, evaluatedWith: id)
        waitForExpectations(timeout: Self.uiTimeout)

        reveal("profile.security.watchtower").tap()
        XCTAssertTrue(element("page.watchtower").waitForExistence(timeout: Self.uiTimeout), "Watchtower not opened")
    }

    /// Two accounts: the panel lists both, and its Profil row opens the Profil.
    func testSecondAccountPanelHasProfilRow() throws {
        try XCTSkipIf(UIDevice.current.userInterfaceIdiom == .pad, "iPhone only")
        launch(["-OnePassDemoSecondAccount", "YES"])
        element("account.menu").tap()
        let row = element("account.profile")
        XCTAssertTrue(row.waitForExistence(timeout: Self.uiTimeout), "panel without its Profil row")
        row.tap()
        XCTAssertTrue(element("profile.account").waitForExistence(timeout: Self.uiTimeout), "Profil not opened")
    }

    /// iPad (regular width, split view): the sidebar's account menu has Profil, and the Profil's rows
    /// open their page there (no tab bar to switch).
    func testIPadAccountMenuOpensProfileAndWatchtower() throws {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .pad, "iPad only")
        element("account.menu").tap()
        // A system menu: its items expose their title, not always their identifier.
        let byID = element("account.profile")
        let item = byID.waitForExistence(timeout: 3) ? byID : app.buttons["Profile"].firstMatch
        XCTAssertTrue(item.waitForExistence(timeout: Self.uiTimeout), "account menu without Profil")
        item.tap()
        XCTAssertTrue(element("profile.account").waitForExistence(timeout: Self.uiTimeout), "Profil not opened")
        reveal("profile.security.watchtower").tap()
        XCTAssertTrue(element("page.watchtower").waitForExistence(timeout: Self.uiTimeout), "Watchtower not opened")
    }
}
