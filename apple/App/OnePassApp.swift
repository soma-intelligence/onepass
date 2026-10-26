import DesignKit
import SwiftUI
import VaultKit

@main
struct OnePassApp: App {
    #if os(iOS)
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
        }
        .defaultSize(width: 1280, height: 820)
        .windowToolbarStyle(.unified)
        .onChange(of: scenePhase) { _, phase in
            model.scenePhaseChanged(phase)
        }
        .commands {
            BrowseCommands(model: model)
        }
        #else
        WindowGroup {
            root
        }
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
#if os(iOS)
final class AppDelegate: NSObject, UIApplicationDelegate {
    var model: AppModel?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        #if ONEPASS_CLOUDKIT
        application.registerForRemoteNotifications()
        #endif
        return true
    }

    func application(
        _ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any]
    ) async -> UIBackgroundFetchResult {
        guard let coordinator = model?.coordinator else { return .noData }
        await coordinator.syncNow()
        return .newData
    }
}
#else
final class AppDelegate: NSObject, NSApplicationDelegate {
    var model: AppModel?

    func applicationDidFinishLaunching(_ notification: Notification) {
        #if ONEPASS_CLOUDKIT
        NSApplication.shared.registerForRemoteNotifications()
        #endif
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
