import DesignKit
import SwiftUI
import UserNotifications
import VaultKit
// The Mac App Store build (ONEPASS_APP_STORE) updates through the store: no Sparkle.
#if os(macOS) && !ONEPASS_APP_STORE
import UpdateKit
#endif

@main
struct OnePassApp: App {
    #if os(iOS) || os(visionOS)
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    #else
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    #endif
    @State private var model = AppModel()
    #if os(macOS) && !ONEPASS_APP_STORE
    /// Updates from GitHub Releases (Sparkle): `nil` in builds without the update key.
    @State private var updater = AppUpdater()
    #endif
    /// Aggregate phase of every scene: drives auto-lock and sync, once for the whole app.
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        // One window in milestone 2: navigation and editing state live in the process-wide
        // `AppModel` (spec 6.3). iPad: `UIApplicationSupportsMultipleScenes` is false.
        #if os(macOS)
        Window("OnePass", id: "main") {
            root
                .frame(minWidth: 820, minHeight: 600)
                // The app outlives its window (menu bar icon): a closed window ends a guest session,
                // as quitting does (ruling A7), but keeps the vault open for the browsers.
                .onDisappear {
                    model.mainWindowClosed()
                }
                // No window-wide material: the split view's sidebar keeps the system's blurred,
                // translucent material while the list and detail stay on the opaque window
                // background (a see-through detail let the desktop wash out labels and cards).
        }
        .defaultSize(width: 1280, height: 820)
        .windowToolbarStyle(.unified)
        // Links (`onepass://`, verification code links) go to the main window, reopened if closed.
        .handlesExternalEvents(matching: ["*"])
        .onChange(of: scenePhase) { _, phase in
            model.scenePhaseChanged(phase)
        }
        .commands {
            BrowseCommands(model: model)
            // View > Show/Hide Sidebar (⌃⌘S): the toolbar has no sidebar button on the Mac.
            SidebarCommands()
            #if !ONEPASS_APP_STORE
            // OnePass > Rechercher les mises à jour…, after À propos.
            CommandGroup(after: .appInfo) {
                if let updater {
                    CheckForUpdatesButton(updater: updater)
                }
            }
            #endif
        }
        // "Ouvrir dans une nouvelle fenêtre" of the item menu: one read-only detail per item.
        WindowGroup(id: ItemWindow.id, for: String.self) { $key in
            ItemWindowRoot(key: key).environment(model).tint(Theme.accent)
        }
        // Never opened by a link: an empty item window would appear.
        .handlesExternalEvents(matching: [])
        .defaultSize(width: 720, height: 780)
        Settings {
            MacSettingsView()
                .environment(model)
                #if !ONEPASS_APP_STORE
                .environment(updater)
                #endif
                .tint(Theme.accent)
        }
        // Menu bar icon: opens the window from anywhere, and the app stays there once the window is
        // closed (the vault stays open until the idle delay, sleep, the screen lock or quitting).
        MenuBarExtra {
            MenuBarMenu(model: model)
        } label: {
            MenuBarLabel(model: model)
        }
        #else
        WindowGroup {
            root
        }
        #if os(visionOS)
        .defaultSize(width: 1280, height: 820)
        #endif
        .onChange(of: scenePhase) { _, phase in
            model.scenePhaseChanged(phase)
        }
        .commands {
            BrowseCommands(model: model)
        }
        #endif
    }

    private var root: some View {
        RootView()
            .environment(model)
            .tint(Theme.accent)
            #if os(iOS)
            .modifier(AppearanceOverride())
            #endif
            .onAppear { appDelegate.model = model }
    }
}

#if os(iOS)
/// Réglages > Général > Apparence on iPhone and iPad: the choice is set on every window of the app
/// (`overrideUserInterfaceStyle`), so sheets, popovers, alerts and the keyboard follow it too.
/// Automatique gives the system's appearance back.
private struct AppearanceOverride: ViewModifier {
    @AppStorage(Appearance.storageKey, store: AppModel.browseDefaults) private var stored = Appearance.system.rawValue
    @Environment(\.scenePhase) private var scenePhase

    func body(content: Content) -> some View {
        content
            .onChange(of: stored, initial: true) { apply() }
            // A window created later (another scene, the privacy cover) picks the choice up here.
            .onChange(of: scenePhase) { apply() }
    }

    private func apply() {
        let style = Appearance(stored: stored).interfaceStyle
        for case let scene as UIWindowScene in UIApplication.shared.connectedScenes {
            for window in scene.windows where window.overrideUserInterfaceStyle != style {
                window.overrideUserInterfaceStyle = style
            }
        }
    }
}
#endif

/// Remote notifications (CloudKit database subscription) start a sync round.
/// Registration only happens in the CloudKit build: the unsigned build has no push entitlement.
/// iPhone: a tapped agent request notification opens the request screen (agent-ready spec 7); the
/// notification itself has no action.
#if os(iOS) || os(visionOS)
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    var model: AppModel?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        // visionOS: no push registration (iOS only).
        #if ONEPASS_CLOUDKIT && os(iOS)
        application.registerForRemoteNotifications()
        UNUserNotificationCenter.current().delegate = self
        #endif
        return true
    }

    #if os(iOS)
    /// The app on screen reads the request itself: no banner.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        []
    }

    /// The request screen opens once the vault is unlocked (it may still be locked here).
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse
    ) async {
        // The CloudKit push of a request only (Watchtower's local alerts open the app as before).
        guard response.notification.request.trigger is UNPushNotificationTrigger else { return }
        await MainActor.run { self.model?.phoneAgents?.notificationTapped() }
    }
    #endif

    func application(
        _ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any]
    ) async -> UIBackgroundFetchResult {
        // A background wake past the auto-lock delay drops the keys before anything else runs.
        model?.session.checkAutoLock()
        guard let model else { return .noData }
        return await model.silentPush() ? .newData : .noData
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        model?.didRegisterPush(token: deviceToken)
    }

    /// Refused or unavailable: the sync still runs at each opening and in the foreground.
    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {}
}
#else
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    var model: AppModel?

    func applicationDidFinishLaunching(_ notification: Notification) {
        #if ONEPASS_CLOUDKIT
        NSApplication.shared.registerForRemoteNotifications()
        #endif
        // Lock on system sleep, on screen lock and when another user takes the screen (fast user
        // switching), like "Tout verrouiller" (no confirmation). With auto-lock on "Jamais" and the
        // window closed, these are what locks an always-on Mac.
        NSWorkspace.shared.notificationCenter.addObserver(
            self, selector: #selector(lockNow), name: NSWorkspace.willSleepNotification, object: nil)
        NSWorkspace.shared.notificationCenter.addObserver(
            self, selector: #selector(lockNow), name: NSWorkspace.sessionDidResignActiveNotification, object: nil)
        DistributedNotificationCenter.default().addObserver(
            self, selector: #selector(lockNow), name: Self.screenLocked, object: nil)
        // No Touch ID prompt on a screen that is asleep or locked (`AppModel.screenAway`): a
        // sleeping display counts too, and each of these ends it.
        NSWorkspace.shared.notificationCenter.addObserver(
            self, selector: #selector(screenAway), name: NSWorkspace.screensDidSleepNotification, object: nil)
        for name in [
            NSWorkspace.didWakeNotification, NSWorkspace.screensDidWakeNotification,
            NSWorkspace.sessionDidBecomeActiveNotification,
        ] {
            NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(screenBack), name: name, object: nil)
        }
        DistributedNotificationCenter.default().addObserver(
            self, selector: #selector(screenBack), name: Self.screenUnlocked, object: nil)
    }

    static let screenLocked = Notification.Name("com.apple.screenIsLocked")
    static let screenUnlocked = Notification.Name("com.apple.screenIsUnlocked")

    @objc private func screenAway() {
        model?.screenWentAway()
    }

    @objc private func screenBack() {
        model?.screenCameBack()
    }

    /// Delivered on the main thread (workspace and distributed notifications both). Every account,
    /// not only the one on screen: the browsers and the agents reach accounts that are not shown.
    @objc private func lockNow() {
        // First: the lock screen this lock brings must not ask Touch ID on a screen going away.
        model?.screenWentAway()
        model?.lockAll()
    }

    /// Quit (the app outlives its window, which no longer locks): locking every account drops the
    /// keys and clears our clipboard value, which macOS would otherwise keep after the process is
    /// gone (no system expiration).
    func applicationWillTerminate(_ notification: Notification) {
        // Quitting or closing the window ends a guest session (ruling A7).
        model?.publicSession?.end()
        model?.lockAll()
    }

    func application(_ application: NSApplication, didReceiveRemoteNotification userInfo: [String: Any]) {
        Task { @MainActor in
            _ = await self.model?.silentPush()
        }
    }

    func application(_ application: NSApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        model?.didRegisterPush(token: deviceToken)
    }

    /// The menu bar icon keeps the app running, the vault as it was (`AppModel.mainWindowClosed`).
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

#if !ONEPASS_APP_STORE
/// OnePass > Rechercher les mises à jour…: Sparkle's window shows what it finds. A view, so the menu
/// item follows `canCheckForUpdates` (disabled while a check or an install runs).
struct CheckForUpdatesButton: View {
    let updater: AppUpdater

    var body: some View {
        Button("menu.app.checkForUpdates") { updater.checkForUpdates() }
            .disabled(!updater.canCheckForUpdates)
    }
}
#endif

/// The menu bar icon. It lives while no window is open, so it reopens the main window when the
/// model asks (`mainWindowRequest`: "Déverrouiller dans OnePass" from an extension).
struct MenuBarLabel: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(systemName: model.session.state == .unlocked ? "key.horizontal.fill" : "key.horizontal")
            .accessibilityLabel(Text("OnePass"))
            .onChange(of: model.mainWindowRequest) {
                openWindow(id: "main")
                NSApp.activate()
            }
    }
}

/// The menu of the menu bar icon: open the window, search, lock, settings, quit.
struct MenuBarMenu: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        Button("app.openOnepass") { show() }
        Button("common.search") {
            show()
            model.searchFocusRequest &+= 1
        }
        Divider()
        Button("Verrouiller") { model.perform(.lock) }
            .disabled(model.session.state != .unlocked)
        Button("Réglages…") {
            NSApp.activate()
            openSettings()
        }
        Divider()
        Button("Quitter OnePass") { NSApp.terminate(nil) }
    }

    private func show() {
        // Opened by hand: the user stays in the app after the unlock (MS-03).
        model.cancelReturnToBrowser()
        openWindow(id: "main")
        NSApp.activate()
    }
}
#endif
