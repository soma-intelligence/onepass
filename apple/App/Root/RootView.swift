import DesignKit
import SwiftUI
import VaultKit

/// Chooses the screen from the session state: onboarding, lock screen, "Données refusées",
/// or the unlocked app. On iPhone and iPad it also drives this window scene's privacy shield.
struct RootView: View {
    @Environment(AppModel.self) private var model
    #if os(iOS)
    @Environment(\.scenePhase) private var scenePhase
    @State private var windowScene: UIWindowScene?
    #endif

    var body: some View {
        content
            .animation(.smooth(duration: 0.25), value: route)
            .onAppear { model.start() }
            #if os(iOS)
            .background { WindowSceneReader(scene: $windowScene).frame(width: 0, height: 0) }
            .onChange(of: scenePhase, initial: true) { _, phase in
                updateShield(phase)
            }
            .onChange(of: windowScene) { _, _ in
                updateShield(scenePhase)
            }
            #endif
    }

    #if os(iOS)
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

/// The unlocked app. Placeholder until the browse screens land (Tasks 14 and 15): shows the
/// selected item's detail when there is one.
struct BrowseRoot: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        NavigationStack {
            content
                .toolbar {
                    ToolbarItem(placement: .navigation) {
                        Button("Verrouiller", systemImage: "lock") { model.lock() }
                            .accessibilityIdentifier("app.lock")
                    }
                }
        }
        .onTapGesture { model.session.noteActivity() }
    }

    @ViewBuilder private var content: some View {
        if let ref = model.selectedItem {
            ItemDetailView(ref: ref).id(ref)
        } else if let draft = debugDraft {
            ItemEditorView(draft: draft, isNew: true) { saved in
                #if DEBUG
                model.debugNewDraft = nil
                #endif
                if let saved { model.selectedItem = ItemRef(vaultID: saved.vaultId, itemID: saved.id) }
            }
        } else {
            EmptyState(
                title: String(localized: "OnePass est déverrouillé"), systemImage: "lock.open",
                message: String(localized: "Les coffres et les éléments s'afficheront ici."))
                .navigationTitle("OnePass")
        }
    }

    private var debugDraft: ItemDraft? {
        #if DEBUG
        model.debugNewDraft
        #else
        nil
        #endif
    }
}
