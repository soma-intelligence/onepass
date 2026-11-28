import XCTest

/// The accessibility tree of the item editor stays responsive: after "Utiliser" in the password
/// generator, a query of the editor answers within a few seconds (it used to time out for more
/// than 90 s, which also silences VoiceOver). Both looks, demonstration data only (Debug
/// `-OnePassDemoData`, fictional values, a temporary database).
@MainActor
final class EditorAccessibilityUITests: XCTestCase {
    private static let launchTimeout: TimeInterval = 90
    /// The answer time the tree must keep after the generator closes.
    private static let responsive: TimeInterval = 5

    override func setUp() {
        continueAfterFailure = false
    }

    func testTreeAnswersAfterGeneratorUseRX() throws {
        try runGeneratorUse(rx: true)
    }

    func testTreeAnswersAfterGeneratorUseClassic() throws {
        try runGeneratorUse(rx: false)
    }

    private func runGeneratorUse(rx: Bool) throws {
        guard UIDevice.current.userInterfaceIdiom == .phone else {
            throw XCTSkip("Runs on an iPhone simulator.")
        }
        let app = XCUIApplication()
        app.launchArguments += [
            "-OnePassDemoData", "YES", "-OnePassDemoBiometrics", "NO",
            "-OnePassDemoItem", "Forge Atlas", "-OnePassDebugEdit", "YES",
            "-OnePassRX", rx ? "YES" : "NO",
        ]
        app.launch()
        let any = app.descendants(matching: .any)

        let save = any["editor.save"].firstMatch
        XCTAssertTrue(save.waitForExistence(timeout: Self.launchTimeout), "editor did not open")

        for round in 1...2 {
            let generate = any.matching(NSPredicate(format: "identifier BEGINSWITH 'editor.generate.'")).firstMatch
            // The password row is in the first card, on screen when the editor opens.
            XCTAssertTrue(generate.waitForExistence(timeout: 10), "no generator button (round \(round))")
            let fieldID = "editor.field." + generate.identifier.dropFirst("editor.generate.".count)
            generate.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
            let use = app.buttons["generator.use"]
            XCTAssertTrue(use.waitForExistence(timeout: 10), "generator did not open (round \(round))")
            use.tap()

            // The sheet goes away, then the editor answers a query quickly.
            let started = Date()
            XCTAssertTrue(
                save.waitForExistence(timeout: Self.responsive),
                "editor did not answer within \(Self.responsive) s after Utiliser (round \(round))")
            XCTAssertTrue(
                any[fieldID].firstMatch.waitForExistence(timeout: Self.responsive),
                "password field missing after Utiliser (round \(round))")
            let elapsed = Date().timeIntervalSince(started)
            XCTAssertLessThan(elapsed, Self.responsive, "tree took \(elapsed) s (round \(round))")
            // A second, independent query: the whole tree, not one cached element.
            XCTAssertTrue(
                any["editor.cancel"].firstMatch.waitForExistence(timeout: Self.responsive),
                "Annuler missing after Utiliser (round \(round))")
            XCTAssertLessThan(
                Date().timeIntervalSince(started), Self.responsive * 2, "tree slow on a second query (round \(round))")
        }
    }

    /// The audit's path: a new login, the username typed with Return (the keyboard moves on to the
    /// masked password field), then the generator from that focused field.
    func testTreeAnswersAfterGeneratorUseFromFocusedFieldRX() throws {
        try runFocusedFieldGeneratorUse(rx: true)
    }

    func testTreeAnswersAfterGeneratorUseFromFocusedFieldClassic() throws {
        try runFocusedFieldGeneratorUse(rx: false)
    }

    private func runFocusedFieldGeneratorUse(rx: Bool) throws {
        guard UIDevice.current.userInterfaceIdiom == .phone else {
            throw XCTSkip("Runs on an iPhone simulator.")
        }
        let app = XCUIApplication()
        app.launchArguments += [
            "-OnePassDemoData", "YES", "-OnePassDemoBiometrics", "NO", "-OnePassDemoNewItem", "YES",
            "-OnePassRX", rx ? "YES" : "NO",
        ]
        app.launch()
        let any = app.descendants(matching: .any)

        let login = any["newItem.login"].firstMatch
        XCTAssertTrue(login.waitForExistence(timeout: Self.launchTimeout), "add sheet did not open")
        // The sheet may still be sliding up: tap once it settled, again if the first tap was lost.
        let title = app.textFields["editor.title"]
        for _ in 0..<3 where !title.exists {
            _ = XCTWaiter.wait(for: [expectation(for: NSPredicate(format: "isHittable == true"), evaluatedWith: login)], timeout: 10)
            login.tap()
            _ = title.waitForExistence(timeout: 8)
        }
        XCTAssertTrue(title.exists, "editor did not open")
        title.tap()
        title.typeText("Exemple Atlas\n")
        let user = app.textFields["editor.field.username"]
        XCTAssertTrue(user.waitForExistence(timeout: 5), "no username field")
        user.tap()
        user.typeText("camille.durand@exemple.fr\n")

        for round in 1...2 {
            let generate = any["editor.generate.password"].firstMatch
            XCTAssertTrue(generate.waitForExistence(timeout: 10), "no generator button (round \(round))")
            generate.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
            let use = app.buttons["generator.use"]
            XCTAssertTrue(use.waitForExistence(timeout: 10), "generator did not open (round \(round))")
            app.buttons["generator.regenerate"].tap()
            use.tap()
            assertResponsive(app, round: round)
        }
    }

    /// The editor answers three independent queries within `responsive` seconds each.
    private func assertResponsive(_ app: XCUIApplication, round: Int, file: StaticString = #filePath, line: UInt = #line) {
        let any = app.descendants(matching: .any)
        for id in ["editor.save", "editor.field.password", "editor.cancel"] {
            let started = Date()
            XCTAssertTrue(
                any[id].firstMatch.waitForExistence(timeout: Self.responsive),
                "\(id) did not answer within \(Self.responsive) s after Utiliser (round \(round))", file: file, line: line)
            XCTAssertLessThan(
                Date().timeIntervalSince(started), Self.responsive, "\(id) slow (round \(round))", file: file, line: line)
        }
    }
}
