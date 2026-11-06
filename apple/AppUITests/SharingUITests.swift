import XCTest

/// Sharing plan 4, Task 9: the sharing screens on the demo account (`-OnePassDemoSharing YES`), a
/// fixed snapshot with no mailbox. They check what is shown and hidden (role rules, badges,
/// reminders, banners), not the actions: sharing, removing or recovering needs v2 accounts with
/// device keys and a mailbox, which the app does not have yet (device check document).
/// Fictional data only (Camille Durand, Léo Martin, Projet Atlas).
@MainActor
final class SharingUITests: XCTestCase {
    /// The demo account is made with the real Argon2id at launch.
    private static let kdfTimeout: TimeInterval = 90
    private static let uiTimeout: TimeInterval = 15

    override func setUp() {
        continueAfterFailure = false
    }

    private func launch(_ extra: [String]) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments += ["-OnePassDemoData", "YES", "-OnePassDemoBiometrics", "NO", "-OnePassDemoSharing", "YES"]
        app.launchArguments += extra
        app.launch()
        return app
    }

    /// Opens `title` from the home's Favoris, scrolling down to its row.
    private func open(_ title: String, in app: XCUIApplication) {
        let row = element(app, "list.row.\(title)")
        XCTAssertTrue(row.waitForExistence(timeout: Self.kdfTimeout), "no \(title) row")
        for _ in 0..<5 where !row.isHittable { app.swipeUp() }
        row.tap()
    }

    private func element(_ app: XCUIApplication, _ id: String) -> XCUIElement {
        app.descendants(matching: .any)[id].firstMatch
    }

    /// Réglages > Contacts: a contact added by link carries "Non vérifié", a verified one does not.
    func testContactAddedByLinkShowsUnverified() {
        let app = launch(["-OnePassDemoSettings", "YES", "-OnePassDemoSettingsPage", "contacts"])
        let leo = element(app, "sharing.contact.Léo Martin")
        XCTAssertTrue(leo.waitForExistence(timeout: Self.kdfTimeout), "no Léo row")
        XCTAssertTrue(element(app, "sharing.contact.Camille Durand").exists, "no Camille row")
        let badges = app.descendants(matching: .any).matching(identifier: "sharing.contact.unverified")
        XCTAssertEqual(badges.count, 1, "one badge expected, on the link contact only")
    }

    /// Réglages > Famille: one organizer, so the reminder to add a second one shows.
    func testFamilyWithOneOrganizerShowsReminder() {
        let app = launch(["-OnePassDemoSettings", "YES", "-OnePassDemoSettingsPage", "family"])
        XCTAssertTrue(element(app, "family.secondOrganizer").waitForExistence(timeout: Self.kdfTimeout), "no reminder")
        XCTAssertTrue(element(app, "family.invite").exists, "an organizer can invite")
    }

    /// An item in a vault shared with this account in Read has no "Modifier"; one in the personal
    /// vault keeps it. Both are favorites, opened from the home.
    func testReadOnlySharedVaultHidesEdit() {
        let app = launch([])
        open("Wi-Fi Maison", in: app)
        XCTAssertTrue(app.staticTexts["item.title"].waitForExistence(timeout: Self.uiTimeout), "item did not open")
        XCTAssertFalse(element(app, "item.edit").exists, "edit shown in a Read vault")

        app.terminate()
        let other = launch([])
        open("Carte Visa Exemple", in: other)
        XCTAssertTrue(other.staticTexts["item.title"].waitForExistence(timeout: Self.uiTimeout), "item did not open")
        XCTAssertTrue(element(other, "item.edit").waitForExistence(timeout: Self.uiTimeout), "edit missing in own vault")
    }

    /// A waiting vault invitation shows a banner over the main window.
    func testInvitationBannerShows() {
        let app = launch([])
        XCTAssertTrue(element(app, "sharing.banner.invites").waitForExistence(timeout: Self.kdfTimeout), "no invitation banner")
    }

    /// A recovery asked by an organizer shows on the lock screen, with its date (spec 11.5).
    func testRecoveryAlertShowsWhileLocked() {
        let app = launch(["-OnePassDemoRecoveryAlert", "YES", "-OnePassDemoLocked", "YES"])
        let message = element(app, "recovery.alert.message")
        XCTAssertTrue(message.waitForExistence(timeout: Self.kdfTimeout), "no recovery alert")
        XCTAssertTrue(message.label.contains("Camille Durand"), "alert without the organizer: \(message.label)")
        XCTAssertFalse(element(app, "sharing.banner.invites").exists, "invitations shown while locked")
    }
}
