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
    #if os(iOS)
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// The vault door playing between the lock screen and the vault (iPhone and iPad).
    @State private var vaultPassage: VaultPassage.Direction?
    #endif

    var body: some View {
        content
            .animation(.smooth(duration: 0.25), value: route)
            #if os(iOS)
            // Unlock: the wheel turns once, the door swings open, the vault shows. Lock: the reverse.
            // Reduce Motion keeps the plain fade.
            .overlay {
                if let direction = vaultPassage {
                    VaultPassage(direction: direction) { vaultPassage = nil }
                        .transition(.opacity)
                }
            }
            #if DEBUG
            // Captures: `-OnePassDemoVaultPassage YES` plays the opening then the closing passage.
            .task {
                guard UserDefaults.standard.bool(forKey: "OnePassDemoVaultPassage") else { return }
                try? await Task.sleep(for: .seconds(1))
                vaultPassage = .opening
                try? await Task.sleep(for: .seconds(2.5))
                vaultPassage = .closing
            }
            #endif
            .onChange(of: route) { old, new in
                guard !reduceMotion else { return }
                if old == .lock, new == .unlocked { vaultPassage = .opening }
                if old == .unlocked, new == .lock { vaultPassage = .closing }
            }
            #endif
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
            #if os(macOS)
            .sheet(item: Binding(
                get: { model.browserBridge?.requests.first },
                set: { _ in }
            )) { request in
                if let bridge = model.browserBridge {
                    BrowserPairingSheet(bridge: bridge, request: request)
                }
            }
            #endif
            #if os(iOS)
            // The requests of the Mac's agents: shown as they arrive or when their notification is
            // tapped, only while the vault is open.
            .sheet(isPresented: Binding(
                get: { model.phoneAgents?.showRequests == true && model.session.state == .unlocked },
                set: { if !$0 { model.phoneAgents?.showRequests = false } }
            )) {
                if let agents = model.phoneAgents {
                    AgentRequestsSheet(agents: agents)
                }
            }
            #endif
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
        case onboarding, lock, unlocked, failed, guest, revoked
    }

    private var route: Route {
        if model.publicSession != nil { return .guest }
        let state = model.session.state
        if state == .failed(.deviceRevoked) { return .revoked }
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
        case .revoked:
            RevokedDeviceView()
                .transition(.opacity)
        case .guest:
            if let guest = model.publicSession {
                PublicSessionView(session: guest) { model.publicSession = nil }
                    .transition(.opacity)
            }
        case .failed:
            if case .failed(let error) = model.session.state {
                IntegrityFailureView(error: error)
            }
        }
    }
}

#if os(iOS)
/// The vault illustration as a short passage over the screen change. Opening: one turn of the
/// wheel, the door swings open, then everything fades into the vault. Closing: the door swings
/// shut over the lock screen, the wheel turns back, then it fades. About 1.3 s, touches pass.
struct VaultPassage: View {
    enum Direction { case opening, closing }

    let direction: Direction
    let done: () -> Void
    @State private var wheel: Double = 0
    @State private var door: Double = 0
    @State private var shown = true

    var body: some View {
        ZStack {
            Color(uiColor: .systemBackground).ignoresSafeArea()
            VaultIllustration(size: 300, tint: Theme.accent, wheelTurn: wheel, doorOpen: door)
        }
        .opacity(shown ? 1 : 0)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
        .task {
            if direction == .closing {
                wheel = 360
                door = 1
                withAnimation(.spring(duration: 0.5, bounce: 0.1)) { door = 0 }
                try? await Task.sleep(for: .milliseconds(450))
                withAnimation(.easeInOut(duration: 0.55)) { wheel = 0 }
                try? await Task.sleep(for: .milliseconds(600))
            } else {
                withAnimation(.easeInOut(duration: 0.6)) { wheel = 360 }
                try? await Task.sleep(for: .milliseconds(600))
                withAnimation(.spring(duration: 0.55, bounce: 0.15)) { door = 1 }
                try? await Task.sleep(for: .milliseconds(450))
            }
            withAnimation(.easeOut(duration: 0.25)) { shown = false }
            try? await Task.sleep(for: .milliseconds(260))
            done()
        }
    }
}
#endif

