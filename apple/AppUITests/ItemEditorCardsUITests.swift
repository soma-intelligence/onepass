import XCTest

/// The item editor in cards (spec 2026-11-13): a second website, a new free section "Banque" with
/// one text field, the websites card dragged below that section by its ☰ handle, saved, reopened.
/// Demonstration data only (Debug `-OnePassDemoData`, fictional values, a temporary database).
@MainActor
final class ItemEditorCardsUITests: XCTestCase {
    private static let timeout: TimeInterval = 90

    override func setUp() {
        continueAfterFailure = false
    }

    func testCardsFlow() throws {
        guard UIDevice.current.userInterfaceIdiom == .phone else {
            throw XCTSkip("Runs on an iPhone simulator.")
        }
        let app = XCUIApplication()
        app.launchArguments += [
            "-OnePassDemoData", "YES", "-OnePassRX", "NO", "-OnePassDemoBiometrics", "NO",
            "-OnePassDemoItem", "Forge Atlas", "-OnePassDebugEdit", "YES",
        ]
        app.launch()
        let any = app.descendants(matching: .any)

        let save = any["editor.save"].firstMatch
        XCTAssertTrue(save.waitForExistence(timeout: Self.timeout), "editor did not open")

        // A second website.
        let addURL = any["editor.addURL"].firstMatch
        scrollTo(addURL, in: app)
        addURL.tap()
        let second = any["editor.url.1"].firstMatch
        XCTAssertTrue(second.waitForExistence(timeout: 5), "second website row missing")
        second.tap()
        second.typeText("https://atlas.exemple.fr")
        second.typeText(XCUIKeyboardKey.return.rawValue)

        // A new section "Banque" with one text field.
        let addMore = any["editor.addField"].firstMatch
        scrollTo(addMore, in: app)
        addMore.tap()
        let addSection = any["editor.addSection"].firstMatch
        XCTAssertTrue(addSection.waitForExistence(timeout: 5), "no Nouvelle section entry")
        addSection.tap()
        let name = sectionName(in: app)
        scrollTo(name, in: app)
        XCTAssertTrue(name.waitForExistence(timeout: 5), "new section card missing")
        let sectionID = Self.sectionID(of: name)
        scrollTo(name, in: app)
        name.tap()
        name.typeText("Banque")
        XCTAssertEqual(name.value as? String, "Banque", "name not typed")
        name.typeText(XCUIKeyboardKey.return.rawValue)
        XCTAssertTrue(app.keyboards.firstMatch.waitForNonExistence(timeout: 5), "keyboard still up")
        let addField = any["editor.section.\(sectionID).addField"].firstMatch
        scrollTo(addField, in: app)
        addField.tap()
        let text = any["editor.addField.custom.text"].firstMatch
        XCTAssertTrue(text.waitForExistence(timeout: 5), "no text field tile")
        text.tap()

        // Drag the websites card below the section.
        let handle = any["editor.reorder.websites"].firstMatch
        scrollTo(handle, in: app)
        let card = any["editor.section.\(sectionID)"].firstMatch
        // A short drag, one slot: just past the middle of the section card, so the drop depends on
        // the measured card frames (a long drag would land last whatever the frames say).
        let below = app.windows.firstMatch.coordinate(withNormalizedOffset: .zero)
            .withOffset(CGVector(dx: handle.frame.midX, dy: card.frame.midY + 10))
        handle.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5))
            .press(forDuration: 0.2, thenDragTo: below, withVelocity: .slow, thenHoldForDuration: 0.3)
        assertWebsitesFollowSection(sectionID, in: app, "before save")

        save.tap()
        let edit = any["item.edit"].firstMatch
        XCTAssertTrue(edit.waitForExistence(timeout: 15), "detail did not come back after save")
        edit.tap()
        XCTAssertTrue(save.waitForExistence(timeout: 10), "editor did not reopen")

        let reopened = sectionName(in: app)
        scrollTo(reopened, in: app)
        XCTAssertTrue(reopened.waitForExistence(timeout: 5), "section lost at save")
        XCTAssertEqual(reopened.value as? String, "Banque")
        assertWebsitesFollowSection(Self.sectionID(of: reopened), in: app, "after reopening")
    }

    // MARK: - Helpers

    /// The name field of the (only) free section: `editor.section.<id>.name`.
    private func sectionName(in app: XCUIApplication) -> XCUIElement {
        app.descendants(matching: .any).matching(
            NSPredicate(format: "identifier BEGINSWITH 'editor.section.' AND identifier ENDSWITH '.name'")
        ).firstMatch
    }

    private static func sectionID(of name: XCUIElement) -> String {
        String(name.identifier.dropFirst("editor.section.".count).dropLast(".name".count))
    }

    private func assertWebsitesFollowSection(
        _ sectionID: String, in app: XCUIApplication, _ moment: String,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        let any = app.descendants(matching: .any)
        let section = any["editor.section.\(sectionID)"].firstMatch
        let websites = any["editor.reorder.websites"].firstMatch
        scrollTo(section, in: app)
        XCTAssertTrue(section.exists && websites.exists, "cards missing \(moment)", file: file, line: line)
        XCTAssertGreaterThan(
            websites.frame.minY, section.frame.minY, "websites card above the section \(moment)",
            file: file, line: line)
    }

    /// Swipes up until the element is on screen (the editor is a scroll view).
    private func scrollTo(_ element: XCUIElement, in app: XCUIApplication) {
        var tries = 0
        while tries < 8, !(element.exists && element.isHittable) {
            app.swipeUp(velocity: .slow)
            tries += 1
        }
    }
}
