import XCTest

/// Réglages on iPhone, on the demo account with a large vault (`-OnePassDemoBulkItems`, fictional
/// logins on `exemple.fr`): it opens at once from the account panel, and its rows do what they say
/// (Ajouter un compte, Nouveau coffre, Suivre les soldes on by default). Debug demo data only.
@MainActor
final class SettingsUITests: XCTestCase {
    /// The demo account (real Argon2id) and a few hundred items: minutes on a busy Mac.
    private static let seedTimeout: TimeInterval = 900
    private static let uiTimeout: TimeInterval = 15
    /// Réglages must be on screen this soon after the tap (it took about a minute on device).
    private static let openBudget: TimeInterval = 3

    private var app: XCUIApplication!

    override func setUp() async throws {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchArguments += [
            "-OnePassDemoData", "YES", "-OnePassDemoBiometrics", "NO", "-OnePassDemoCrypto", "NO",
            "-OnePassDemoBulkItems", "300",
        ]
        app.launch()
        let menu = element("account.menu")
        XCTAssertTrue(menu.waitForExistence(timeout: Self.seedTimeout), "demo vault not shown")
        // The seeding goes on after the first screen: wait for the last bulk item.
        let search = NSPredicate(format: "identifier == 'list.row.Site exemple 300' OR label CONTAINS 'Site exemple 300'")
        _ = app.descendants(matching: .any).matching(search).firstMatch.waitForExistence(timeout: 5)
    }

    private func element(_ id: String) -> XCUIElement {
        app.descendants(matching: .any)[id].firstMatch
    }

    /// Account panel > Réglages: the sheet's first frame within the budget, three times in a row.
    private func openSettings() -> TimeInterval {
        let menu = element("account.menu")
        XCTAssertTrue(menu.waitForExistence(timeout: Self.uiTimeout))
        menu.tap()
        let row = element("account.settings")
        XCTAssertTrue(row.waitForExistence(timeout: Self.uiTimeout), "account panel without Réglages")
        let start = Date()
        row.tap()
        let done = element("settings.done")
        let shown = done.waitForExistence(timeout: 90)
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertTrue(shown, "Réglages never opened")
        return elapsed
    }

    private func closeSettings() {
        element("settings.done").tap()
        XCTAssertTrue(element("settings.done").waitForNonExistence(timeout: Self.uiTimeout))
    }

    func testSettingsOpensAtOnceOnALargeVault() throws {
        var times: [TimeInterval] = []
        for _ in 0..<3 {
            times.append(openSettings())
            closeSettings()
        }
        let report = times.map { String(format: "%.2f s", $0) }.joined(separator: ", ")
        add(XCTAttachment(string: "Réglages opened after: \(report)"))
        print("settings-open-times: \(report)")
        for time in times {
            XCTAssertLessThan(time, Self.openBudget, "Réglages took \(report)")
        }
    }

    func testAddAccountOpensFromSettings() throws {
        _ = openSettings()
        element("settings.accounts").tap()
        let add = element("settings.accounts.add")
        XCTAssertTrue(add.waitForExistence(timeout: Self.uiTimeout))
        add.tap()
        let cancel = element("accounts.add.dismiss")
        XCTAssertTrue(cancel.waitForExistence(timeout: Self.uiTimeout), "Ajouter un compte did not open")
        cancel.tap()
        XCTAssertTrue(cancel.waitForNonExistence(timeout: Self.uiTimeout))
        XCTAssertTrue(add.waitForExistence(timeout: Self.uiTimeout), "Réglages > Comptes lost after cancel")
        app.navigationBars.buttons.element(boundBy: 0).tap()
        XCTAssertTrue(element("settings.done").waitForExistence(timeout: Self.uiTimeout))
        closeSettings()

        // The account panel's own "Ajouter un compte" (a sheet of the root, after the popover).
        element("account.menu").tap()
        let panelAdd = element("accounts.add")
        XCTAssertTrue(panelAdd.waitForExistence(timeout: Self.uiTimeout), "account panel without Ajouter un compte")
        panelAdd.tap()
        XCTAssertTrue(cancel.waitForExistence(timeout: 5), "Ajouter un compte did not open from the account panel")
        cancel.tap()
    }

    func testNewVaultFromSettingsShowsInTheList() throws {
        _ = openSettings()
        element("settings.vaults").tap()
        let new = element("settings.vaults.new")
        XCTAssertTrue(new.waitForExistence(timeout: Self.uiTimeout))
        new.tap()
        let name = element("vault.editor.name")
        XCTAssertTrue(name.waitForExistence(timeout: Self.uiTimeout), "Nouveau coffre did not open")
        name.tap()
        name.typeText("Coffre Exemple UI")
        element("vault.editor.save").tap()
        XCTAssertTrue(name.waitForNonExistence(timeout: Self.uiTimeout), "editor still open after Créer")
        let row = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS 'Coffre Exemple UI'")).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: Self.uiTimeout), "new vault missing from Réglages > Coffres")
        XCTAssertTrue(new.exists, "Réglages > Coffres lost after Créer")
    }

    func testEverySettingsPageOpens() throws {
        _ = openSettings()
        let pages = ["settings.account", "settings.general", "settings.security", "settings.autofill", "settings.sync",
                     "settings.accounts", "settings.vaults", "settings.devices", "settings.travel",
                     "settings.crypto", "settings.watch", "settings.agents", "settings.about"]
        for id in pages {
            let row = element(id)
            var swipes = 0
            while !(row.exists && row.isHittable), swipes < 3 {
                app.swipeUp()
                swipes += 1
            }
            XCTAssertTrue(row.waitForExistence(timeout: Self.uiTimeout), "row \(id) missing")
            row.tap()
            let back = app.navigationBars.buttons.element(boundBy: 0)
            XCTAssertTrue(back.waitForExistence(timeout: Self.uiTimeout), "\(id) did not push a page")
            sleep(1)
            let shot = XCTAttachment(screenshot: app.screenshot())
            shot.name = id
            shot.lifetime = .keepAlways
            add(shot)
            back.tap()
            XCTAssertTrue(element("settings.done").waitForExistence(timeout: Self.uiTimeout), "\(id): back to Réglages failed")
        }
    }
}
