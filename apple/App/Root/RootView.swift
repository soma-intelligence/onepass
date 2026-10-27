import DesignKit
import GlanceKit
import SwiftUI
import VaultKit

/// Chooses the screen from the session state: onboarding, lock screen, "Données refusées",
/// or the unlocked app. On iPhone and iPad it also drives this window scene's privacy shield.
struct RootView: View {
    @Environment(AppModel.self) private var model
    #if os(iOS) || os(visionOS)
    @Environment(\.scenePhase) private var scenePhase
    @State private var windowScene: UIWindowScene?
    #endif

    var body: some View {
        content
            .animation(.smooth(duration: 0.25), value: route)
            .onAppear { model.start() }
            .onChange(of: model.session.state) { _, state in
                model.sessionStateChanged(state)
            }
            // Favorites, titles and codes of the widgets follow the data.
            .onChange(of: model.session.summaries) {
                model.companion.sessionChanged()
            }
            // A vault hidden on this device leaves the widgets too.
            .onChange(of: model.session.hiddenVaultIDs) {
                model.companion.sessionChanged()
            }
            // A route kept during the onboarding (its account creation unlocks first).
            .onChange(of: model.onboardingInProgress) { _, inProgress in
                if !inProgress { model.consumePendingRoute() }
            }
            .onOpenURL { url in
                // Anything but the three `onepass://` links is ignored.
                if let link = OnePassLink(url: url) { model.open(link) }
            }
            // After the first password unlock where biometrics could be on (`AppModel.biometricOffer`).
            // Only the buttons answer: the setter must not race "Activer" with a refusal.
            .alert(
                Text("Utiliser \(OnboardingModel.biometryName) pour déverrouiller ?"),
                isPresented: Binding(
                    get: { model.biometricOffer != nil && model.session.state == .unlocked },
                    set: { _ in }),
                presenting: model.biometricOffer
            ) { _ in
                Button("Activer") { model.answerBiometricOffer(accept: true) }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("biometricOffer.enable")
                Button("Plus tard", role: .cancel) { model.answerBiometricOffer(accept: false) }
                    .accessibilityIdentifier("biometricOffer.later")
            } message: { _ in
                Text("La prochaine fois, \(OnboardingModel.biometryName) suffit pour ouvrir OnePass. Le mot de passe maître reste demandé tous les 14 jours et après un redémarrage.")
            }
            #if os(iOS) || os(visionOS)
            .background { WindowSceneReader(scene: $windowScene).frame(width: 0, height: 0) }
            .onChange(of: scenePhase, initial: true) { _, phase in
                updateShield(phase)
            }
            .onChange(of: windowScene) { _, _ in
                updateShield(scenePhase)
            }
            #endif
    }

    #if os(iOS) || os(visionOS)
    /// Above every presentation (sheets, share sheet, alerts): a window of its own (spec 9).
    private func updateShield(_ phase: ScenePhase) {
        guard let windowScene else { return }
        PrivacyShieldWindows.shared.setVisible(phase != .active, in: windowScene)
    }
    #endif

    private enum Route: Hashable {
        case onboarding, lock, unlocked, failed
    }

    private var route: Route {
        let state = model.session.state
        if case .failed = state { return .failed }
        if model.onboardingInProgress || state == .noAccount { return .onboarding }
        // An account is in the store but this device lacks its Secret Key: Emergency Kit.
        if model.session.needsSecretKey, state != .unlocked { return .onboarding }
        return state == .unlocked ? .unlocked : .lock
    }

    @ViewBuilder private var content: some View {
        switch route {
        case .onboarding:
            OnboardingFlow()
                .transition(.opacity)
        case .lock:
            LockView()
                .transition(.opacity)
        case .unlocked:
            BrowseRoot()
                .transition(.opacity)
        case .failed:
            if case .failed(let error) = model.session.state {
                IntegrityFailureView(error: error)
            }
        }
    }
}
