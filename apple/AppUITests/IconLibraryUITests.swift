import XCTest

/// The icon library (spec 2026-11-14 part D): the editor's icon menu, "Choisir une icône…", a pack
/// logo picked in Logos, saved; the item's list row then draws the chosen icon
/// (`list.row.icon.custom`). Demonstration data only (Debug `-OnePassDemoData`, fictional values, a
/// temporary database).
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
            "-OnePassDemoData", "YES", "-OnePassRX", "NO", "-OnePassDemoBiometrics", "NO", "-OnePassDemoList", "all",
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
        // The row's icon carries `list.row.icon.custom` once it draws the chosen icon.
        let icon = row.descendants(matching: .any)["list.row.icon.custom"].firstMatch
        let anyIcon = any["list.row.icon.custom"].firstMatch
        XCTAssertTrue(
            icon.waitForExistence(timeout: 15) || anyIcon.exists, "the list row does not draw the chosen icon")
        attach("icon-library-list")
    }

    private func attach(_ name: String) {
        let shot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        shot.name = name
        shot.lifetime = .keepAlways
        add(shot)
    }
}

/// All Items in the RX look (Penpot "RX · All Items v2"): the header count, the letter sections,
/// the chips (Favoris narrows and clears, the order toggles without a menu), the swipe actions,
/// the no-result state with its one action, and the accessibility sizes. Demonstration data only
/// (Debug `-OnePassDemoData`, fictional values). It lives in this file so the shared project needs
/// no regeneration.
@MainActor
final class RXAllItemsUITests: XCTestCase {
    private static let timeout: TimeInterval = 120
    private static let ui: TimeInterval = 10

    override func setUp() {
        continueAfterFailure = false
    }

    private func launch(_ extra: [String] = []) throws -> XCUIApplication {
        guard UIDevice.current.userInterfaceIdiom == .phone else {
            throw XCTSkip("Runs on an iPhone simulator.")
        }
        let app = XCUIApplication()
        app.launchArguments += [
            "-OnePassDemoData", "YES", "-OnePassRX", "YES", "-OnePassDemoBiometrics", "NO", "-OnePassDemoCrypto", "NO",
            "-OnePassDemoTab", "items", "-OnePassDemoList", "all", "-AppleLanguages", "(fr)", "-AppleLocale", "fr_FR",
        ] + extra
        app.launch()
        XCTAssertTrue(element(app, "rx.list.count").waitForExistence(timeout: Self.timeout), "RX All Items not shown")
        return app
    }

    private func element(_ app: XCUIApplication, _ id: String) -> XCUIElement {
        app.descendants(matching: .any)[id].firstMatch
    }

    func testChipsSortSwipeAndEmptySearch() throws {
        let app = try launch()
        let amex = element(app, "list.row.Amex Platinum")
        XCTAssertTrue(amex.waitForExistence(timeout: Self.ui), "no Amex Platinum row")
        XCTAssertTrue(element(app, "rx.list.section.A").exists, "no letter section A")

        // Favoris narrows the list to the favourites, a second tap clears it.
        let favorites = element(app, "rx.list.chip.favorites")
        XCTAssertTrue(favorites.waitForExistence(timeout: Self.ui), "no Favoris chip")
        favorites.tap()
        XCTAssertTrue(amex.waitForNonExistence(timeout: Self.ui), "Favoris kept a row that is not a favourite")
        XCTAssertTrue(element(app, "list.row.Camille Durand").waitForExistence(timeout: Self.ui), "favourite missing")
        favorites.tap()
        XCTAssertTrue(amex.waitForExistence(timeout: Self.ui), "Favoris did not clear")

        // The order is one tap: by modification there are no letter sections, then back.
        let sort = element(app, "rx.list.sort")
        sort.tap()
        XCTAssertTrue(element(app, "rx.list.section.A").waitForNonExistence(timeout: Self.ui), "letters kept by date")
        sort.tap()
        XCTAssertTrue(element(app, "rx.list.section.A").waitForExistence(timeout: Self.ui), "letters not back")

        // Swipe from the right: Archive first, then Supprimer.
        amex.swipeLeft()
        XCTAssertTrue(element(app, "list.swipe.archive").waitForExistence(timeout: Self.ui), "no Archive swipe action")
        XCTAssertTrue(element(app, "list.swipe.trash").exists, "no Supprimer swipe action")
        amex.swipeRight()

        // A search that finds nothing says so, with one action that clears it.
        let field = app.searchFields.firstMatch
        if !field.exists { app.swipeDown() }
        XCTAssertTrue(field.waitForExistence(timeout: Self.ui), "no search field")
        field.tap()
        field.typeText("zzqx")
        XCTAssertTrue(element(app, "list.empty.search").waitForExistence(timeout: Self.ui), "no no-result state")
        let clear = app.buttons["Effacer la recherche"].firstMatch
        XCTAssertTrue(clear.waitForExistence(timeout: Self.ui), "no Effacer la recherche action")
        clear.tap()
        XCTAssertTrue(amex.waitForExistence(timeout: Self.ui), "rows not back after clearing the search")
    }

    func testAccessibilitySizesKeepRowsReachable() throws {
        let app = try launch(["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"])
        let row = element(app, "list.row.Agenda Exemple")
        XCTAssertTrue(row.waitForExistence(timeout: Self.ui), "first row missing at AX5")
        XCTAssertTrue(element(app, "rx.list.sort").exists, "sort chip missing at AX5")
        row.tap()
        XCTAssertTrue(element(app, "item.title").waitForExistence(timeout: Self.ui), "row did not open its item")
    }

    func testAccessibilityAudit() throws {
        let app = try launch()
        RunLoop.current.run(until: Date().addingTimeInterval(2))
        try app.performAccessibilityAudit(for: [.sufficientElementDescription, .hitRegion, .dynamicType]) { issue in
            // Account initials inside the fixed avatar disc, the system's own bar controls, and the
            // system section index (UIKit's own A to Z rail: its letters are narrow by design and it
            // takes the drag along the whole edge).
            let label = issue.element?.label ?? ""
            let systemIndex = ["Index de section", "Section index", "Índice de sección", "Indice di sezione"].contains(label)
            return label == "CD" || issue.element?.elementType == .tabBar || systemIndex
        }
    }
}
