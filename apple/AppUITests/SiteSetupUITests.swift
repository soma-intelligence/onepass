import XCTest

/// Site setup offers from the signed site pack (wave 2) on iPhone, on the demo vault: the 2FA
/// Watchtower list shows the setup button on a row, and the item's banner can be ignored and
/// restored. The demo login "GitHub" (Personnel, https://github.com/login) has no code, and the
/// shipped pack lists github.com with totp. Debug demo data only, no network.
@MainActor
final class SiteSetupUITests: XCTestCase {
    /// The demo account derives a real Argon2id key: minutes on a busy Mac.
    private static let seedTimeout: TimeInterval = 600
    private static let uiTimeout: TimeInterval = 30

    private var app: XCUIApplication!

    override func setUp() async throws {
        continueAfterFailure = false
    }

    private func element(_ id: String) -> XCUIElement {
        app.descendants(matching: .any)[id].firstMatch
    }

    /// Scrolls until `target` is on screen.
    private func reveal(_ target: XCUIElement) -> XCUIElement {
        var tries = 0
        while !(target.exists && target.isHittable), tries < 8 {
            app.swipeUp()
            tries += 1
        }
        return target
    }

    func testTwoFactorBannerAndRowButton() throws {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .phone, "iPhone only")
        app = XCUIApplication()
        app.launchArguments += [
            "-OnePassDemoData", "YES", "-OnePassDemoBiometrics", "NO", "-OnePassDemoCrypto", "NO",
            "-OnePassDemoTab", "watchtower",
        ]
        app.launch()
        XCTAssertTrue(element("page.watchtower").waitForExistence(timeout: Self.seedTimeout), "Watchtower not shown")

        // The 2FA card lists the GitHub login, with its setup button on the row.
        let card = element("watchtower.show.2fa")
        XCTAssertTrue(card.waitForExistence(timeout: Self.uiTimeout), "no 2FA card")
        reveal(card).tap()
        let row = element("list.row.GitHub")
        XCTAssertTrue(row.waitForExistence(timeout: Self.uiTimeout), "GitHub not in the 2FA list")
        let setup = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'watchtower.setup.'")).firstMatch
        XCTAssertTrue(setup.waitForExistence(timeout: Self.uiTimeout), "no setup button on the rows")

        // The item's banner: ignored, then restored from its Watchtower section.
        row.tap()
        let banner = element("item.twoFactorOffer")
        XCTAssertTrue(banner.waitForExistence(timeout: Self.uiTimeout), "no 2FA banner on GitHub")
        element("item.twoFactorOffer.ignore").tap()
        XCTAssertTrue(banner.waitForNonExistence(timeout: Self.uiTimeout), "banner still shown after Ignorer")
        let restore = element("item.watchtower.restore.missing_2fa")
        XCTAssertTrue(reveal(restore).exists, "no Rétablir in the item's Watchtower section")
        restore.tap()
        XCTAssertTrue(restore.waitForNonExistence(timeout: Self.uiTimeout), "check still ignored")
        app.swipeDown()
        app.swipeDown()
        XCTAssertTrue(banner.waitForExistence(timeout: Self.uiTimeout), "banner not back after Rétablir")
    }
}
