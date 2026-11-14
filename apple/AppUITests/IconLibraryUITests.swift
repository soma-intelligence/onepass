import XCTest

/// The icon library (spec 2026-11-14 part D): the editor's icon menu, "Choisir une icône…", a pack
/// logo picked in Logos, saved; the item's list row then draws the chosen icon. Demonstration data
/// only (Debug `-OnePassDemoData`, fictional values, a temporary database).
@MainActor
final class IconLibraryUITests: XCTestCase {
    private static let timeout: TimeInterval = 90
    private static let title = "Forge Atlas"
    private static let chooseLabels = ["Choisir une icône…", "Choose an icon…", "Elegir un icono…", "Scegli un'icona…"]

    override func setUp() {
        continueAfterFailure = false
    }

    func testPickPackLogoShowsInList() throws {
        guard UIDevice.current.userInterfaceIdiom == .phone else {
            throw XCTSkip("Runs on an iPhone simulator.")
        }
        let app = XCUIApplication()
        app.launchArguments += [
            "-OnePassDemoData", "YES", "-OnePassDemoBiometrics", "NO", "-OnePassDemoList", "all",
            "-OnePassDemoItem", Self.title, "-OnePassDebugEdit", "YES",
        ]
        app.launch()
        let any = app.descendants(matching: .any)

        let save = any["editor.save"].firstMatch
        XCTAssertTrue(save.waitForExistence(timeout: Self.timeout), "editor did not open")

        let menu = any["editor.icon"].firstMatch
        XCTAssertTrue(menu.waitForExistence(timeout: 5), "no icon menu")
        menu.tap()
        // A menu's buttons lose their identifier on iOS: found by label too, in the four languages.
        let byID = any["editor.icon.choose"].firstMatch
        let byLabel = app.buttons.matching(NSPredicate(format: "label IN %@", Self.chooseLabels)).firstMatch
        XCTAssertTrue(byID.waitForExistence(timeout: 5) || byLabel.exists, "no Choisir une icône… entry")
        (byID.exists ? byID : byLabel).tap()

        let search = any["iconLibrary.search"].firstMatch
        XCTAssertTrue(search.waitForExistence(timeout: 10), "icon library did not open")
        search.tap()
        search.typeText("github")
        let first = any["iconLibrary.logo.0"].firstMatch
        XCTAssertTrue(first.waitForExistence(timeout: 10), "no logo found for github")
        XCTAssertTrue(first.label.localizedCaseInsensitiveContains("github"), "first logo is \(first.label)")
        attach("icon-library-logos")
        first.tap()
        XCTAssertTrue(search.waitForNonExistence(timeout: 5), "sheet still open after the pick")

        save.tap()
        let edit = any["item.edit"].firstMatch
        XCTAssertTrue(edit.waitForExistence(timeout: 15), "detail did not come back after save")
        app.navigationBars.buttons.element(boundBy: 0).tap()

        // All Items is long and lazy: swipe until the row is built.
        let row = any["list.row.\(Self.title)"].firstMatch
        var swipes = 0
        while !row.waitForExistence(timeout: 2), swipes < 12 {
            app.swipeUp(velocity: .fast)
            swipes += 1
        }
        XCTAssertTrue(row.exists, "list row missing")
        let custom = NSPredicate(format: "value == %@", "custom")
        expectation(for: custom, evaluatedWith: row)
        waitForExpectations(timeout: 15)
        attach("icon-library-list")
    }

    private func attach(_ name: String) {
        let shot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        shot.name = name
        shot.lifetime = .keepAlways
        add(shot)
    }
}
