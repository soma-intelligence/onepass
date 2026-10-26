import DesignKit
import SwiftUI
import VaultKit

/// Chooses the screen from the session state: onboarding, lock screen, "Données refusées",
/// or the unlocked app. Adds the privacy shield on iPhone and iPad.
struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        content
            .animation(.smooth(duration: 0.25), value: route)
            #if os(iOS)
            .overlay {
                if scenePhase != .active { PrivacyShield() }
            }
            #endif
            .onAppear { model.start() }
            .onChange(of: scenePhase, initial: false) { _, phase in
                model.scenePhaseChanged(phase)
            }
    }

    private enum Route: Hashable {
        case onboarding(restoreOnly: Bool), lock, unlocked, failed
    }

    private var route: Route {
        let state = model.session.state
        if case .failed = state { return .failed }
        if model.onboardingInProgress || state == .noAccount { return .onboarding(restoreOnly: false) }
        // An account is in the store but this device lacks its Secret Key: Emergency Kit.
        if model.session.needsSecretKey, state != .unlocked { return .onboarding(restoreOnly: true) }
        return state == .unlocked ? .unlocked : .lock
    }

    @ViewBuilder private var content: some View {
        switch route {
        case .onboarding(let restoreOnly):
            OnboardingFlow(restoreOnly: restoreOnly)
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

/// The unlocked app. Placeholder until the browse screens land (Tasks 14 and 15).
struct BrowseRoot: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        NavigationStack {
            EmptyState(
                title: "OnePass est déverrouillé", systemImage: "lock.open",
                message: "Les coffres et les éléments s'afficheront ici.")
                .navigationTitle("OnePass")
                .toolbar {
                    ToolbarItem(placement: .primaryAction) {
                        Button("Verrouiller", systemImage: "lock") { model.lock() }
                    }
                }
        }
        .onTapGesture { model.session.noteActivity() }
    }
}
