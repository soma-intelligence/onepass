import DesignKit
import SwiftUI
import VaultKit

@main
struct OnePassApp: App {
    #if os(iOS) || os(visionOS)
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    #else
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    #endif
    @State private var model = AppModel()
    /// Aggregate phase of every scene: drives auto-lock and sync, once for the whole app.
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        // One window in milestone 2: navigation and editing state live in the process-wide
        // `AppModel` (spec 6.3). iPad: `UIApplicationSupportsMultipleScenes` is false.
        #if os(macOS)
        Window("OnePass", id: "main") {
            root
                .frame(minWidth: 820, minHeight: 600)
                // The desktop shows through, blurred: columns and cards stay see-through.
                .containerBackground(.thinMaterial, for: .window)
        }
        .defaultSize(width: 1280, height: 820)
        .windowToolbarStyle(.unified)
        .onChange(of: scenePhase) { _, phase in
            model.scenePhaseChanged(phase)
        }
        .commands {
            BrowseCommands(model: model)
            // View > Show/Hide Sidebar (⌃⌘S): the toolbar has no sidebar button on the Mac.
            SidebarCommands()
        }
        // "Ouvrir dans une nouvelle fenêtre" of the item menu: one read-only detail per item.
        WindowGroup(id: ItemWindow.id, for: String.self) { $key in
            ItemWindowRoot(key: key).environment(model).tint(Theme.accent)
        }
        .defaultSize(width: 720, height: 780)
        Settings {
            MacSettingsView()
                .environment(model)
                .tint(Theme.accent)
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
            .onAppear { appDelegate.model = model }
    }
}

/// Remote notifications (CloudKit database subscription) start a sync round.
/// Registration only happens in the CloudKit build: the unsigned build has no push entitlement.
#if os(iOS) || os(visionOS)
final class AppDelegate: NSObject, UIApplicationDelegate {
    var model: AppModel?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        // visionOS: no push registration (iOS only).
        #if ONEPASS_CLOUDKIT && os(iOS)
        application.registerForRemoteNotifications()
        #endif
        return true
    }

    func application(
        _ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any]
    ) async -> UIBackgroundFetchResult {
        // A background wake past the auto-lock delay drops the keys before anything else runs.
        model?.session.checkAutoLock()
        guard let coordinator = model?.coordinator else { return .noData }
        await coordinator.syncNow()
        return .newData
    }
}
#else
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    var model: AppModel?

    func applicationDidFinishLaunching(_ notification: Notification) {
        #if ONEPASS_CLOUDKIT
        NSApplication.shared.registerForRemoteNotifications()
        #endif
        // Lock on system sleep and on screen lock, like the lock button (no confirmation).
        NSWorkspace.shared.notificationCenter.addObserver(
            self, selector: #selector(lockNow), name: NSWorkspace.willSleepNotification, object: nil)
        DistributedNotificationCenter.default().addObserver(
            self, selector: #selector(lockNow), name: Self.screenLocked, object: nil)
    }

    static let screenLocked = Notification.Name("com.apple.screenIsLocked")

    /// Delivered on the main thread (workspace and distributed notifications both).
    @objc private func lockNow() {
        model?.lock()
    }

    /// Quit (also after the last window closed): `lock()` drops the keys and clears our clipboard
    /// value, which macOS would otherwise keep after the process is gone (no system expiration).
    func applicationWillTerminate(_ notification: Notification) {
        model?.lock()
    }

    func application(_ application: NSApplication, didReceiveRemoteNotification userInfo: [String: Any]) {
        Task { @MainActor in
            guard let coordinator = self.model?.coordinator else { return }
            await coordinator.syncNow()
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
#endif
