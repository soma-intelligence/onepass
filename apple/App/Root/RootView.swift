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
    /// The split-screen passage playing between the lock screen and the vault (iPhone and iPad).
    @State private var vaultPassage: VaultPassage.Direction?
    #endif

    var body: some View {
        content
            .animation(.smooth(duration: 0.25), value: route)
            #if os(iOS)
            // Unlock: the mark turns, the screen splits open onto the vault. Lock: the reverse.
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
                // The three `onepass://` links and the verification code links; anything else is
                // ignored. A code link waits for the unlock like the others.
                if let link = OnePassLink(url: url) {
                    model.open(link)
                } else if OtpLink.handles(url) {
                    model.handle(.otpLink(url.absoluteString))
                }
            }
            // After the first password unlock where biometrics could be on (`AppModel.biometricOffer`).
            // Only the buttons answer: the setter must not race "Activer" with a refusal.
            .alert(
                Text("Utiliser \(OnboardingModel.biometryName) pour déverrouiller ?"),
                isPresented: Binding(
                    get: {
                        model.biometricOffer != nil && model.session.state == .unlocked
                            && !model.session.canUseBiometrics
                    },
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
/// A short passage over the screen change: the screen splits at its middle with the Lattice mark
/// on the seam. Opening: the mark gives a quick quarter turn, then the top half slides up and the
/// bottom half slides down onto the vault while the mark shrinks away. Closing: the halves slide
/// in and meet over the lock screen, the mark turns back, then the passage fades. About 0.5 s,
/// touches pass. Reduce Motion: a plain quick crossfade.
struct VaultPassage: View {
    enum Direction { case opening, closing }

    let direction: Direction
    let done: () -> Void
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.displayScale) private var displayScale
    /// 0: the halves meet at the seam. 1: both are off screen.
    @State private var parted: CGFloat
    @State private var turn: Double
    @State private var markShown: Bool
    @State private var shown: Bool

    init(direction: Direction, done: @escaping () -> Void) {
        self.direction = direction
        self.done = done
        let opening = direction == .opening
        _parted = State(initialValue: opening ? 0 : 1)
        _turn = State(initialValue: opening ? 0 : 90)
        _markShown = State(initialValue: opening)
        _shown = State(initialValue: true)
    }

    var body: some View {
        GeometryReader { proxy in
            let travel = proxy.size.height / 2 + 24
            ZStack {
                VStack(spacing: 0) {
                    half(seamAtBottom: true).offset(y: -parted * travel)
                    half(seamAtBottom: false).offset(y: parted * travel)
                }
                AppGlyph(size: 88)
                    .rotationEffect(.degrees(turn))
                    .scaleEffect(markShown ? 1 : 0.6)
                    .opacity(markShown ? 1 : 0)
            }
        }
        .ignoresSafeArea()
        .opacity(shown ? 1 : 0)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
        .task {
            if reduceMotion {
                await crossfade()
            } else if direction == .opening {
                await open()
            } else {
                await close()
            }
            done()
        }
    }

    /// One half of the screen in the system background, a hairline and a soft shadow on its seam edge.
    private func half(seamAtBottom: Bool) -> some View {
        Color(uiColor: .systemBackground)
            .overlay(alignment: seamAtBottom ? .bottom : .top) {
                Rectangle()
                    .fill(Color(uiColor: .separator))
                    .frame(height: 1 / displayScale)
            }
            .shadow(color: .black.opacity(0.14), radius: 10, y: seamAtBottom ? 3 : -3)
            .zIndex(seamAtBottom ? 1 : 0)
    }

    private func open() async {
        withAnimation(.snappy(duration: 0.22)) { turn = 90 }
        try? await Task.sleep(for: .milliseconds(120))
        withAnimation(.spring(duration: 0.36, bounce: 0)) { parted = 1 }
        withAnimation(.easeOut(duration: 0.2)) { markShown = false }
        try? await Task.sleep(for: .milliseconds(360))
    }

    private func close() async {
        withAnimation(.spring(duration: 0.3, bounce: 0)) { parted = 0 }
        withAnimation(.easeOut(duration: 0.2).delay(0.08)) { markShown = true }
        try? await Task.sleep(for: .milliseconds(240))
        withAnimation(.snappy(duration: 0.22)) { turn = 0 }
        try? await Task.sleep(for: .milliseconds(200))
        withAnimation(.easeOut(duration: 0.14)) { shown = false }
        try? await Task.sleep(for: .milliseconds(150))
    }

    /// Reduce Motion: no slide, no turn. The halves stay closed and the cover fades.
    private func crossfade() async {
        parted = 0
        turn = 0
        markShown = true
        if direction == .closing {
            shown = false
            withAnimation(.easeOut(duration: 0.12)) { shown = true }
            try? await Task.sleep(for: .milliseconds(130))
        }
        withAnimation(.easeOut(duration: 0.18)) { shown = false }
        try? await Task.sleep(for: .milliseconds(190))
    }
}
#endif

