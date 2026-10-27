import DesignKit
import SwiftUI

/// Covers the whole window while the scene is not active (app switcher snapshot, Control Center,
/// system sheets), so no vault content is ever captured (spec 9). Opaque on purpose: a blur would
/// still let shapes and colors through.
struct PrivacyShield: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.background)
            AppGlyph(size: 88)
        }
        .ignoresSafeArea()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("OnePass masqué"))
    }
}

#if os(iOS) || os(visionOS)
/// One shield window per window scene, at a level above alerts, so it also covers sheets and the
/// share sheet presented by the scene's windows. Shown while the scene is not active.
@MainActor
final class PrivacyShieldWindows {
    static let shared = PrivacyShieldWindows()
    private var windows: [ObjectIdentifier: UIWindow] = [:]

    func setVisible(_ visible: Bool, in scene: UIWindowScene) {
        let key = ObjectIdentifier(scene)
        // Drop windows of scenes that went away.
        windows = windows.filter { $0.value.windowScene != nil }
        if visible {
            let window = windows[key] ?? makeWindow(scene)
            windows[key] = window
            window.isHidden = false
        } else {
            windows[key]?.isHidden = true
        }
    }

    private func makeWindow(_ scene: UIWindowScene) -> UIWindow {
        let window = UIWindow(windowScene: scene)
        window.windowLevel = .alert + 1
        let host = UIHostingController(rootView: PrivacyShield())
        host.view.backgroundColor = .systemBackground
        window.rootViewController = host
        window.accessibilityViewIsModal = true
        return window
    }
}

/// Hands the hosting window's scene to SwiftUI.
struct WindowSceneReader: UIViewRepresentable {
    @Binding var scene: UIWindowScene?

    func makeUIView(context: Context) -> ReaderView {
        let view = ReaderView()
        view.onScene = { scene in
            if self.scene !== scene { self.scene = scene }
        }
        return view
    }

    func updateUIView(_ view: ReaderView, context: Context) {}

    final class ReaderView: UIView {
        var onScene: ((UIWindowScene?) -> Void)?

        override func didMoveToWindow() {
            super.didMoveToWindow()
            onScene?(window?.windowScene)
        }
    }
}
#endif

#Preview("PrivacyShield") {
    PrivacyShield()
}
