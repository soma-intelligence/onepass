import SwiftUI
#if os(iOS) || os(visionOS)
import UIKit
#endif

/// Guards a view that shows the Secret Key (spec 4): while the scene is recorded, mirrored or
/// AirPlayed (`isSceneCaptured`) the content is replaced by a placeholder, and a screenshot taken
/// while it is on screen raises a warning. No effect on macOS, which has neither signal.
struct SecretKeyCaptureGuard: ViewModifier {
    #if os(iOS) || os(visionOS)
    @Environment(\.isSceneCaptured) private var captured
    @State private var screenshotTaken = false
    #endif

    func body(content: Content) -> some View {
        #if os(iOS) || os(visionOS)
        content
            .opacity(captured ? 0 : 1)
            .accessibilityHidden(captured)
            .overlay {
                if captured {
                    Label("Secret Key masquée pendant l'enregistrement ou la recopie de l'écran",
                          systemImage: "eye.slash")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .accessibilityIdentifier("secretKey.captureMask")
                }
            }
            .onReceive(NotificationCenter.default.publisher(
                for: UIApplication.userDidTakeScreenshotNotification)) { _ in
                    screenshotTaken = true
                }
            .alert("Capture d'écran de ta Secret Key", isPresented: $screenshotTaken) {
                Button("OK", role: .cancel) {}
            } message: {
                Text("Cette capture contient ta Secret Key. Supprime-la de Photos, puis de l'album Supprimés récemment : Photos et iCloud peuvent la copier hors de cet appareil.")
            }
        #else
        content
        #endif
    }
}

extension View {
    /// See `SecretKeyCaptureGuard`. Apply to every view that shows the Secret Key.
    func secretKeyCaptureGuard() -> some View {
        modifier(SecretKeyCaptureGuard())
    }
}
