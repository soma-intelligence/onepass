import AppKit
import os

/// "OnePass Fill", the login item that fills logins outside the browsers (spec
/// 2026-11-23-mac-fill-anywhere-design). An agent app (`LSUIElement`): no window, no menu, no Dock
/// icon. It reaches the Mac app through `BridgeLink` and keeps running.
@main
@MainActor
final class OnePassFillApp: NSObject, NSApplicationDelegate {
    /// `NSApplication.delegate` is weak: the delegate lives here.
    private static var delegate: OnePassFillApp?

    private let link = BridgeLink()
    private let log = Logger(subsystem: Bundle.main.bundleIdentifier ?? "me.somalabs.onepass.fill", category: "app")

    static func main() {
        let app = NSApplication.shared
        let delegate = OnePassFillApp()
        Self.delegate = delegate
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        app.run()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task {
            let status = await link.status()
            log.notice("bridge status: \(String(describing: status), privacy: .public)")
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}
