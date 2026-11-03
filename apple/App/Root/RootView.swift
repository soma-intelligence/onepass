import AuthenticationServices
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
    /// The vault door between the lock screen and the vault (iPhone and iPad, `VaultDoorPassage`).
    @State private var door = VaultDoorPassage()
    /// The lock screen as it was at the end of the dial's turn: the two panels of the opening door.
    @State private var doorSnapshot: UIImage?
    /// The dial's center (global y): where the door splits.
    @State private var doorSeam: CGFloat?
    /// Bumped by each passage: a completion of a replaced passage is ignored.
    @State private var doorGeneration = 0
    #if DEBUG
    @State private var demoDoorPlayed = false
    #endif
    #endif
    /// Credentials handed over by another app (Credential Exchange), waiting for the unlock.
    @State private var credentialExchange: CredentialExchangeRequest?

    var body: some View {
        content
            // Sharing notices. iPhone: on the lock screen only, the home shows them in its blocks
            // (its large header draws under the top inset).
            .safeAreaInset(edge: .top, spacing: 0) {
                if showsRootSharingBanners { SharingBanners() }
            }
            .animation(.smooth(duration: 0.25), value: route)
            #if os(iOS)
            .environment(\.vaultDialTurn, door.dialTurn)
            .onPreferenceChange(VaultSeamKey.self) { seam in
                // The last place the dial was seen: it stays put once the lock screen leaves.
                MainActor.assumeIsolated { if let seam { doorSeam = seam } }
            }
            .overlay { doorOverlay }
            // A catch as the dial turns, a firmer one as the bolt releases and the door parts.
            .sensoryFeedback(trigger: door.phase) { _, phase in
                switch phase {
                case .turning: .impact(flexibility: .rigid, intensity: 0.5)
                case .parting: .impact(weight: .medium, intensity: 0.8)
                default: nil
                }
            }
            .onChange(of: route) { old, new in
                routeChanged(from: old, to: new)
            }
            #endif
            .onAppear { model.start() }
            .onChange(of: model.session.state) { old, state in
                model.sessionStateChanged(state, from: old)
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
                guard !inProgress else { return }
                // A new account's onboarding ended: its account is bound to its slot.
                model.finishAddingAccountIfNeeded()
                model.consumePendingRoute()
            }
            // The services bound to the primary account follow its state, whichever account shows.
            .onChange(of: model.primarySession.state) { _, state in
                model.primaryStateChanged(state)
            }
            // Passwords > Export Data to Another App > OnePass: the import sheet opens on what the
            // other app sends (passkeys included) once the vault is unlocked.
            .onContinueUserActivity(ASCredentialExchangeActivity) { activity in
                if let token = CredentialExchangeImport.token(of: activity) {
                    credentialExchange = CredentialExchangeRequest(token: token)
                }
            }
            .sheet(item: Binding(
                get: { model.session.state == .unlocked ? credentialExchange : nil },
                set: { if $0 == nil { credentialExchange = nil } }
            )) { request in
                ImportSheet(credentialExchange: request.token)
            }
            .onOpenURL { url in
                // The three `onepass://` links and the verification code links; anything else is
                // ignored. A code link waits for the unlock like the others.
                #if os(macOS)
                if BrowserBridge.isUnlockLink(url) {
                    model.showForUnlock()
                    return
                }
                #endif
                if let link = OnePassLink(url: url) {
                    model.open(link)
                } else if OtpLink.handles(url) {
                    model.handle(.otpLink(url.absoluteString))
                }
            }
            // After the first password unlock where biometrics could be on (`AppModel.biometricOffer`).
            // Only the buttons answer: the setter must not race "Activer" with a refusal.
            .alert(
                Text("root.useToUnlock \(OnboardingModel.biometryName)"),
                isPresented: Binding(
                    get: {
                        model.biometricOffer != nil && model.session.state == .unlocked
                            && !model.session.canUseBiometrics && !doorHoldsPresentations
                    },
                    set: { _ in }),
                presenting: model.biometricOffer
            ) { _ in
                Button("app.turnOn") { model.answerBiometricOffer(accept: true) }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("biometricOffer.enable")
                Button("app.later", role: .cancel) { model.answerBiometricOffer(accept: false) }
                    .accessibilityIdentifier("biometricOffer.later")
            } message: { _ in
                Text("root.nextTimeAllIt \(OnboardingModel.biometryName)")
            }
            // Multi-account (spec 7): adding an account, from the account panel, the lock screen or
            // Réglages > Comptes; the search over every unlocked account when the user chose it.
            .sheet(isPresented: Binding(
                get: { model.showAddAccount }, set: { model.showAddAccount = $0 })) {
                AddAccountSheet()
            }
            .sheet(isPresented: Binding(
                get: { model.showAllAccountsSearch && model.accounts.unifiedSearch },
                set: { model.showAllAccountsSearch = $0 })) {
                AllAccountsSearch()
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
                #if os(iOS)
                // The door never outlives the scene going to the background (its completions may
                // not come back): the screen is simply the vault or the lock screen again. Not on
                // `.inactive`: the Face ID sheet makes the scene inactive around the unlock itself.
                if phase == .background, door.isActive {
                    doorGeneration &+= 1
                    doorSnapshot = nil
                    door.handle(.interrupted)
                }
                #endif
            }
            .onChange(of: windowScene) { _, _ in
                updateShield(scenePhase)
            }
            // The lock screen's own Face ID prompt makes the scene inactive: the shield stays down
            // for it, so the prompt rises over the lock screen and its dial, not a blank cover.
            .onChange(of: model.biometricAutoPrompt.promptOnScreen) { _, _ in
                updateShield(scenePhase)
            }
            #endif
    }

    #if os(iOS) || os(visionOS)
    /// Above every presentation (sheets, share sheet, alerts): a window of its own (spec 9). Not
    /// over the lock screen's own biometric prompt, nor while its sheet leaves after a success (the
    /// dial turns and the door opens right then); always in the background, where the app switcher
    /// takes its picture.
    private func updateShield(_ phase: ScenePhase) {
        guard let windowScene else { return }
        let visible = model.biometricAutoPrompt.shieldVisible(in: BiometricAutoPrompt.Phase(phase))
        PrivacyShieldWindows.shared.setVisible(visible, in: windowScene)
    }
    #endif

    #if os(iOS)
    private var doorKeepsLock: Bool { door.keepsLockOnTop }
    private var doorHoldsPresentations: Bool { door.holdsPresentations }
    private var doorShowsVault: Bool { door.showsVaultUnderneath }
    private var vaultScale: CGFloat { door.vaultScale }
    #else
    private var doorKeepsLock: Bool { false }
    private var doorHoldsPresentations: Bool { false }
    private var doorShowsVault: Bool { false }
    private var vaultScale: CGFloat { 1 }
    #endif

    private enum Route: Hashable {
        case onboarding, lock, unlocked, failed, guest, revoked, erased
        #if DEBUG
        /// Demo data: its account is being made and filled.
        case demoPreparing
        #endif
    }

    private var route: Route {
        if model.publicSession != nil { return .guest }
        let state = model.session.state
        if state == .failed(.deviceRevoked) { return .revoked }
        if case .failed = state { return .failed }
        // The quarantine erased this device: why, once, before the onboarding.
        if state == .noAccount, model.session.erasedByQuarantine != nil { return .erased }
        #if DEBUG
        if model.demoPreparing { return .demoPreparing }
        #endif
        if model.onboardingInProgress || state == .noAccount { return .onboarding }
        // An account is in the store but this device lacks its Secret Key: Emergency Kit.
        if model.session.needsSecretKey, state != .unlocked { return .onboarding }
        return state == .unlocked ? .unlocked : .lock
    }

    private var showsRootSharingBanners: Bool {
        #if os(iOS)
        if UIDevice.current.userInterfaceIdiom == .phone { return route == .lock }
        #endif
        return true
    }

    @ViewBuilder private var content: some View {
        switch route {
        case .onboarding:
            OnboardingFlow()
                // A new account's sign up: the account shown before is one tap away.
                .id(model.accounts.activeSlot)
                .overlay(alignment: .topLeading) {
                    if model.canCancelAddingAccount {
                        Button("common.cancel") { model.cancelAddingAccount() }
                            .buttonStyle(.glass)
                            .padding()
                            .accessibilityIdentifier("accounts.add.cancel")
                    }
                }
                .transition(.opacity)
        case .lock, .unlocked:
            // One branch for both, so the lock screen can stay above the vault while the door
            // opens (the same `LockView`, never a second one: its automatic Face ID runs once).
            // One view per account: nothing typed or shown for one account stays for another.
            ZStack {
                if route == .unlocked || doorShowsVault {
                    BrowseRoot()
                        .id(model.accounts.activeSlot)
                        .scaleEffect(vaultScale)
                        .transition(.opacity)
                }
                if route == .lock || doorKeepsLock {
                    LockView()
                        .id(model.accounts.activeSlot)
                        // Under the door, the lock screen leaves at once: the panels are its picture.
                        .transition(doorKeepsLock ? .identity : .opacity)
                }
            }
            .transition(.opacity)
        case .revoked:
            RevokedDeviceView()
                .transition(.opacity)
        case .erased:
            ErasedDeviceView()
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
        #if DEBUG
        case .demoPreparing:
            ProgressView()
                .controlSize(.large)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .accessibilityIdentifier("demo.preparing")
                .transition(.opacity)
        #endif
        }
    }
}

#if os(iOS)
// MARK: - Vault door

extension RootView {
    @ViewBuilder private var doorOverlay: some View {
        switch door.phase {
        case .parting:
            if let snapshot = doorSnapshot {
                let generation = doorGeneration
                VaultDoorOpening(snapshot: snapshot, seam: doorSeam) {
                    doorEvent(.panelsOpened, generation: generation)
                }
                .transition(.identity)
            }
        case .closing, .fading:
            let generation = doorGeneration
            VaultDoorClosingPassage {
                doorEvent(.panelsClosed, generation: generation)
            } faded: {
                doorEvent(.fadeFinished, generation: generation)
            }
            .transition(.identity)
        case .idle, .turning:
            EmptyView()
        }
    }

    /// Started by the session's real state change (`route`), never by a timer around the unlock.
    private func routeChanged(from old: Route, to new: Route) {
        doorGeneration &+= 1
        let generation = doorGeneration
        if old == .lock, new == .unlocked {
            var next = door
            next.handle(.unlocked(reduceMotion: reduceMotion))
            guard next.phase == .turning else {
                door = next
                announceUnlocked()
                return
            }
            // The dial turns with a little catch at the end; the vault is already rendered below.
            withAnimation(.spring(duration: 0.3, bounce: 0.18), completionCriteria: .logicallyComplete) {
                door = next
            } completion: {
                turnFinished(generation: generation)
            }
            #if DEBUG
            demoLockIfAsked()
            #endif
        } else if old == .unlocked, new == .lock {
            doorSnapshot = nil
            // A lock in the background (auto-lock, app switcher) plays nothing nobody sees.
            door.handle(.locked(reduceMotion: reduceMotion || scenePhase == .background))
        } else {
            doorSnapshot = nil
            door.handle(.interrupted)
            #if DEBUG
            if new == .unlocked { demoLockIfAsked() }
            #endif
        }
    }

    /// The dial is at rest a quarter turn on: the lock screen is captured as it is on screen and
    /// replaced by its picture in two panels, which part while the vault settles to full size.
    private func turnFinished(generation: Int) {
        guard generation == doorGeneration, door.phase == .turning else { return }
        guard let snapshot = captureWindow() else {
            withAnimation(.smooth(duration: 0.25)) { door.handle(.captureFailed) }
            announceUnlocked()
            return
        }
        doorSnapshot = snapshot
        withAnimation(VaultDoorOpening.animation) { door.handle(.turnFinished) }
    }

    private func doorEvent(_ event: VaultDoorPassage.Event, generation: Int) {
        guard generation == doorGeneration else { return }
        let wasOpening = door.phase == .parting
        door.handle(event)
        guard !door.isActive else { return }
        doorSnapshot = nil
        if wasOpening { announceUnlocked() }
    }

    /// What is on screen right now (the last frame drawn, `afterScreenUpdates: false`): the lock
    /// screen with its dial turned. The picture lives only while the door opens; it holds nothing
    /// secret (the password field is empty once an unlock is under way).
    private func captureWindow() -> UIImage? {
        guard let window = windowScene?.windows.first(where: \.isKeyWindow) ?? windowScene?.windows.first,
            window.bounds.width > 0, window.bounds.height > 0
        else { return nil }
        let renderer = UIGraphicsImageRenderer(bounds: window.bounds)
        return renderer.image { _ in
            _ = window.drawHierarchy(in: window.bounds, afterScreenUpdates: false)
        }
    }

    /// VoiceOver hears it once the vault is the screen (the door itself is hidden from it).
    private func announceUnlocked() {
        AccessibilityNotification.Announcement(String(localized: "lock.unlockedAnnouncement")).post()
    }

    #if DEBUG
    /// Captures and the fold showcase: `-OnePassDemoVaultPassage YES` locks the demo vault once,
    /// a second after it opens; the lock screen then plays a refused try and a real unlock
    /// (`LockView`), so the door opens through the session's own path.
    private func demoLockIfAsked() {
        guard UserDefaults.standard.bool(forKey: "OnePassDemoVaultPassage"), !demoDoorPlayed else { return }
        demoDoorPlayed = true
        Task {
            try? await Task.sleep(for: .seconds(1.5))
            model.lock()
        }
    }
    #endif
}

/// The opening door, its own animation started as it appears (so it parts from closed).
private struct VaultDoorOpening: View {
    static let animation: Animation = .spring(duration: 0.42, bounce: 0)

    let snapshot: UIImage
    let seam: CGFloat?
    let opened: () -> Void
    @State private var parted: CGFloat = 0

    var body: some View {
        GeometryReader { proxy in
            VaultDoorPanels(snapshot: snapshot, seam: seam ?? proxy.size.height / 2, parted: parted)
        }
        .ignoresSafeArea()
        .onAppear {
            withAnimation(Self.animation, completionCriteria: .logicallyComplete) {
                parted = 1
            } completion: {
                opened()
            }
        }
    }
}

/// The closing door: the panels slide in and meet, then fade onto the lock screen below.
private struct VaultDoorClosingPassage: View {
    let closed: () -> Void
    let faded: () -> Void
    @State private var parted: CGFloat = 1
    @State private var opacity: Double = 1

    var body: some View {
        VaultDoorClosing(parted: parted, opacity: opacity)
            .onAppear {
                withAnimation(.spring(duration: 0.32, bounce: 0), completionCriteria: .logicallyComplete) {
                    parted = 0
                } completion: {
                    closed()
                    withAnimation(.easeOut(duration: 0.18)) {
                        opacity = 0
                    } completion: {
                        faded()
                    }
                }
            }
    }
}
#endif

/// One Credential Exchange hand-over: its one-time token.
private struct CredentialExchangeRequest: Identifiable {
    let token: UUID
    var id: UUID { token }
}
