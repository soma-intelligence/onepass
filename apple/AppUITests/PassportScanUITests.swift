import XCTest

/// The passport scan on iPhone (NFC documents spec 6.2), on the demo account. `-OnePassFakeChip
/// YES` (Debug only) replaces the camera with the ICAO specimen MRZ of the core's replay fixture
/// and the chip with a fake that answers that specimen (verified, drawn portrait); any other MRZ
/// meets a real core session against a chip that refuses the keys. `-OnePassFakeChipMRZ other`
/// makes the camera read another valid MRZ. `-OnePassDemoNewItem YES` opens the new item sheet.
@MainActor
final class PassportScanUITests: XCTestCase {
    private static let seedTimeout: TimeInterval = 900
    private static let uiTimeout: TimeInterval = 30

    private var app: XCUIApplication!

    override func setUp() async throws {
        continueAfterFailure = false
    }

    private func launch(otherMRZ: Bool = false) {
        app = XCUIApplication()
        app.launchArguments += [
            "-OnePassDemoData", "YES", "-OnePassDemoBiometrics", "NO", "-OnePassDemoCrypto", "NO",
            "-OnePassDemoNewItem", "YES", "-OnePassFakeChip", "YES",
            "-AppleLanguages", "(fr)", "-AppleLocale", "fr_FR",
        ]
        if otherMRZ { app.launchArguments += ["-OnePassFakeChipMRZ", "other"] }
        app.launch()
        XCTAssertTrue(element("newItem.scan").waitForExistence(timeout: Self.seedTimeout), "no Scanner in the new item sheet")
    }

    private func element(_ id: String) -> XCUIElement {
        app.descendants(matching: .any)[id].firstMatch
    }

    private func text(containing value: String) -> XCUIElement {
        app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", value)).firstMatch
    }

    private func tap(_ id: String, _ message: String) {
        let target = element(id)
        XCTAssertTrue(target.waitForExistence(timeout: Self.uiTimeout), message)
        target.tap()
    }

    /// "Scanner" > Passeport > fake camera > "Lire la puce": up to the result of the read.
    private func scanUpToRead() {
        tap("newItem.scan", "no Scanner")
        tap("scan.entry.passport", "Que veux-tu ajouter ? without Passeport")
        XCTAssertTrue(element("scan.place.title").waitForExistence(timeout: Self.uiTimeout), "the MRZ was not found")
        XCTAssertTrue(app.staticTexts["Pose ton téléphone sur le document."].exists)
        tap("scan.read", "no Lire la puce")
    }

    /// A full scan of the specimen, saved: the detail of the new passport is on screen.
    private func scanNewPassport() {
        scanUpToRead()
        let save = element("scan.save")
        XCTAssertTrue(save.waitForExistence(timeout: Self.uiTimeout), "no reveal after the read")
        XCTAssertTrue(element("scan.booklet").exists, "no booklet in the reveal")
        save.tap()
        XCTAssertTrue(save.waitForNonExistence(timeout: Self.uiTimeout), "scan still open after Enregistrer")
    }

    /// The booklet of the detail opened: the chip portrait, read back from its attachment, shows.
    private func assertPortraitInDetail(_ message: String) {
        tap("document.passport.cover", "no closed booklet in the detail")
        XCTAssertTrue(app.images["Photo de la puce"].waitForExistence(timeout: Self.uiTimeout), message)
    }

    /// The detail's files: exactly one, the chip portrait. The section's identifier covers its
    /// rows, so a file is counted by its row ("portrait.jpg, 11 ko") and its actions button.
    private func assertOnePortraitFile() {
        let portraits = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "portrait.jpg,"))
        let fileActions = app.buttons.matching(NSPredicate(format: "label == %@", "Actions sur le fichier"))
        var swipes = 0
        while !portraits.firstMatch.exists, swipes < 8 {
            app.swipeUp()
            swipes += 1
        }
        XCTAssertTrue(portraits.firstMatch.waitForExistence(timeout: Self.uiTimeout), "no portrait file on the passport")
        XCTAssertEqual(portraits.count, 1, "the old portrait was not removed")
        XCTAssertEqual(fileActions.count, 1, "the passport holds another file")
    }

    func testScanCreatesPassport() throws {
        launch()
        scanNewPassport()
        XCTAssertTrue(text(containing: "Passeport UTO").waitForExistence(timeout: Self.uiTimeout), "no Passeport UTO")
        XCTAssertTrue(
            text(containing: "Authentifié par la puce").waitForExistence(timeout: Self.uiTimeout),
            "no chip badge on the new passport")
        assertPortraitInDetail("no chip portrait in the new passport's booklet")
    }

    func testWrongMrzShowsAccessDenied() throws {
        launch(otherMRZ: true)
        scanUpToRead()
        let error = element("scan.error")
        XCTAssertTrue(error.waitForExistence(timeout: Self.uiTimeout), "no error after a refused read")
        XCTAssertEqual(error.label, "La puce a refusé l'accès. Les lignes scannées ne correspondent pas.")
        XCTAssertTrue(element("scan.rescan").exists, "no Rescanner la MRZ")
        XCTAssertFalse(element("scan.save").exists)
    }

    func testRescanMergesWithoutOverwriting() throws {
        launch()
        scanNewPassport()
        XCTAssertTrue(text(containing: "Passeport UTO").waitForExistence(timeout: Self.uiTimeout), "no Passeport UTO")

        // The given names typed by hand: "Anna" instead of the chip's "Anna Maria".
        tap("item.edit", "no Modifier on the passport")
        let names = element("editor.field.first_names")
        XCTAssertTrue(names.waitForExistence(timeout: Self.uiTimeout), "no Prénoms in the editor")
        var swipes = 0
        while !names.isHittable, swipes < 6 {
            app.swipeUp()
            swipes += 1
        }
        names.coordinate(withNormalizedOffset: CGVector(dx: 0.95, dy: 0.5)).tap()
        names.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: 16) + "Anna")
        tap("editor.save", "no Enregistrer in the editor")
        XCTAssertTrue(element("editor.save").waitForNonExistence(timeout: Self.uiTimeout), "editor still open")
        XCTAssertTrue(app.staticTexts["Anna"].waitForExistence(timeout: Self.uiTimeout), "edited names not shown")

        // Scanner la puce: the chip says "Anna Maria", the typed value stays and the conflict shows.
        tap("item.menu", "no actions menu")
        tap("item.scanChip", "no Scanner la puce")
        XCTAssertTrue(element("scan.place.title").waitForExistence(timeout: Self.uiTimeout), "the MRZ was not found")
        tap("scan.read", "no Lire la puce")
        let conflict = element("scan.conflict.first_names")
        XCTAssertTrue(conflict.waitForExistence(timeout: Self.uiTimeout), "no conflict on the given names")
        XCTAssertTrue(conflict.buttons["Anna"].exists, "the typed value is not offered")
        XCTAssertTrue(conflict.buttons["Anna Maria"].exists, "the chip's value is not offered")
        XCTAssertTrue(conflict.buttons["Anna"].isSelected, "the typed value is not the default")
        tap("scan.save", "no Enregistrer")
        XCTAssertTrue(element("scan.save").waitForNonExistence(timeout: Self.uiTimeout), "scan still open")

        XCTAssertTrue(app.staticTexts["Anna"].waitForExistence(timeout: Self.uiTimeout), "the typed names were lost")
        XCTAssertFalse(app.staticTexts["Anna Maria"].exists, "the chip overwrote the typed names")
        XCTAssertTrue(text(containing: "Authentifié par la puce").exists, "no chip badge after the second read")
        assertPortraitInDetail("no chip portrait after the second read")
        assertOnePortraitFile()
    }
}
