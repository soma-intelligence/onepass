import DesignKit
import SwiftUI
import VaultKit

/// Lock screen: one centered column (on the window's glass on Mac): the app glyph, "Déverrouille
/// OnePass", the account (badge and name), ONE master password field (show or hide button, accent
/// focus ring, shakes on a wrong password) and below it the main action: "Déverrouiller avec
/// Touch ID" (Face ID, Optic ID) while the field is empty and biometric unlock is on, otherwise
/// "Déverrouiller". Return unlocks. The Secret Key is never asked here: it stays in this device's
/// keychain. Biometric unlock is tried at most once per lock presentation, automatically, once this
/// screen has been seen for a moment in an active scene (`BiometricAutoPrompt`): never over the
/// launch screen or the privacy cover, and never again after that prompt answers (success, cancel or
/// failure), whatever scene phases its sheet causes; after it only the button asks. While the system
/// checks, the dial is worked tick by tick; it opens into the vault door on success and unwinds
/// against its stop on a refusal.
struct LockView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var password = ""
    @State private var revealed = false
    @State private var message: String?
    @State private var lockoutRefresh = 0
    /// Bumped on each refused password: the field shakes.
    @State private var refusals = 0
    /// The keyboard focus of the password field (`SecretInputField` reaches its UIKit field both ways).
    @State private var fieldFocused = false
    /// Bumped on each refused Face ID (Touch ID, Optic ID) try: the dial jiggles against its stop.
    @State private var dialRefusals = 0
    /// "J'ai perdu mon mot de passe ou ma Secret Key" is open.
    @State private var recovering = false
    /// The system biometric check is running: the dial is being worked.
    @State private var biometricCheck = false
    /// This lock screen is in the view hierarchy (the automatic try waits for it).
    @State private var shown = false

    private var session: VaultSession { model.session }
    private var unlocking: Bool { session.state == .unlocking }
    private var biometrics: Bool { session.canUseBiometrics }

    #if os(macOS)
    private static let glyphSize: CGFloat = 72
    private static let fieldHeight: CGFloat = 40
    private static let buttonHeight: CGFloat = 30
    private static let columnWidth: CGFloat = 300
    #else
    private static let glyphSize: CGFloat = 84
    private static let dialSize: CGFloat = 120
    private static let fieldHeight: CGFloat = 50
    private static let buttonHeight: CGFloat = 36
    private static let columnWidth: CGFloat = 340
    #endif

    var body: some View {
        ZStack {
            background
            layout
        }
        .task(id: lockoutUntil) {
            // Re-renders when the wait ends so the field and the button come back.
            guard let until = lockoutUntil else { return }
            try? await Task.sleep(for: .seconds(max(0, until.timeIntervalSinceNow) + 0.2))
            lockoutRefresh &+= 1
        }
        .onAppear { shown = true }
        .onDisappear { shown = false }
        .task(id: AutoAttempt(presentation: model.biometricAutoPrompt.presentation, ready: shown && scenePhase == .active)) {
            // At most one automatic try per lock presentation (`BiometricAutoPrompt`): this task
            // runs again on every scene phase change (the Face ID sheet causes some), but only a
            // real lock makes a new try due. It waits until this screen has been on screen, active
            // and uncovered, for a moment: run at once, the system prompt rose over the launch
            // screen or the privacy cover before the lock screen was ever seen. The password field
            // takes the focus (and the keyboard comes up) only when no biometric check runs.
            guard shown, scenePhase == .active else { return }
            #if DEBUG && os(iOS)
            if await playDemoVaultDoor() { return }
            #endif
            if model.automaticBiometricAttemptDue, session.canUseBiometrics {
                do {
                    try await Task.sleep(for: BiometricAutoPrompt.settle)
                } catch {
                    return
                }
                if model.takeAutomaticBiometricAttempt(), session.canUseBiometrics {
                    // Not tied to this task: the prompt makes the scene inactive, which ends this
                    // task, and a cancelled task would dismiss the system sheet (`decrypt`).
                    Task { await unlockWithBiometrics(automatic: true) }
                    return
                }
            }
            if session.state == .locked, !biometricCheck, !model.biometricAutoPrompt.promptOnScreen {
                fieldFocused = true
            }
        }
    }

    /// Every platform: the column centered in the window, scrolling only when it does not fit
    /// (iPhone in landscape, large text).
    private var layout: some View {
        GeometryReader { geometry in
            ScrollView {
                column
                    .frame(maxWidth: Self.columnWidth)
                    .padding(.horizontal, 28)
                    .padding(.vertical, 40)
                    #if os(visionOS)
                    .glassBackgroundEffect()
                    #endif
                    // A little above the middle, where the eye lands first.
                    .padding(.bottom, geometry.size.height > 560 ? 48 : 0)
                    .frame(maxWidth: .infinity, minHeight: geometry.size.height)
            }
            .scrollBounceBehavior(.basedOnSize)
            .scrollIndicators(.hidden)
        }
    }

    private var column: some View {
        VStack(spacing: 0) {
            #if os(iOS)
            // The vault's dial: it turns, and the screen opens at its center (`RootView`).
            VaultDial(size: Self.dialSize, refusals: dialRefusals, working: biometricCheck)
            #else
            AppGlyph(size: Self.glyphSize)
            #endif
            Text("lock.unlockOnepass")
                .font(.system(size: Platform.isMac ? 22 : 26, weight: .semibold))
                .multilineTextAlignment(.center)
                .padding(.top, 20)
                .accessibilityAddTraits(.isHeader)
            account
                .padding(.top, 10)
            passwordField
                .padding(.top, 26)
            status
        }
        .animation(.smooth(duration: 0.2), value: password.isEmpty)
        .animation(.smooth(duration: 0.2), value: message)
    }

    private var background: some View {
        #if os(iOS)
        Color(uiColor: .systemGroupedBackground).ignoresSafeArea()
        #else
        // Mac: the window's translucent glass (`containerBackground`); Vision Pro: the system glass.
        Color.clear
        #endif
    }

    // MARK: - Account

    /// The account to unlock; with several accounts on the device, a menu that switches to another
    /// (each keeps its own lock and Secret Key, multi-account spec 2).
    @ViewBuilder private var account: some View {
        if model.accounts.hasSeveralAccounts {
            Menu {
                AccountsMenuItems()
            } label: {
                accountCapsule(chevron: true)
            }
            .menuStyle(.button)
            .buttonStyle(.plain)
            .menuIndicator(.hidden)
            .fixedSize()
            .accessibilityIdentifier("lock.accounts")
        } else {
            accountCapsule(chevron: false)
        }
    }

    @ViewBuilder private func accountCapsule(chevron: Bool) -> some View {
        let profile = model.activeProfile
        let initials = profile.map { $0.isPrimary ? model.initials : model.initials(of: $0) } ?? model.initials
        let name = profile.flatMap { $0.label.isEmpty ? nil : $0.label } ?? model.settings.displayName
        HStack(spacing: 8) {
            // Round, so it sits concentric in the capsule (a squircle poked out of it).
            if let photo = model.profileImage {
                photo
                    .resizable()
                    .scaledToFill()
                    .frame(width: 26, height: 26)
                    .clipShape(Circle())
                    .overlay { Circle().strokeBorder(.white.opacity(0.15), lineWidth: 0.5) }
            } else {
                Circle()
                    .fill(model.accountTint)
                    .frame(width: 26, height: 26)
                    .overlay {
                        if initials.isEmpty {
                            Image(systemName: "person.fill").font(.system(size: 11)).foregroundStyle(.white)
                        } else {
                            Text(verbatim: initials)
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundStyle(.white)
                        }
                    }
            }
            Group {
                if name.isEmpty {
                    Text("lock.onepassAccount")
                } else {
                    Text(verbatim: name)
                }
            }
            .font(.subheadline.weight(.medium))
            .foregroundStyle(.secondary)
            .lineLimit(1)
            if chevron {
                Image(systemName: "chevron.up.chevron.down")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.leading, 3)
        .padding(.trailing, 12)
        .padding(.vertical, 3)
        .background(Capsule().fill(Color.primary.opacity(0.06)))
        .fixedSize()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(name.isEmpty ? Text("lock.onepassAccount") : Text(verbatim: name))
        .accessibilityIdentifier("lock.account")
    }

    // MARK: - Password

    private var passwordField: some View {
        let shape = RoundedRectangle(cornerRadius: Platform.isMac ? 10 : 14, style: .continuous)
        let ring: Color = message != nil ? .red : (fieldFocused ? Theme.accent : .clear)
        return HStack(spacing: 4) {
            // Emptied as it leaves the screen: iOS never offers to save the master password (ruling X24).
            SecretInputField(
                title: String(localized: "Mot de passe maître"), text: $password, revealed: revealed,
                focused: $fieldFocused, submitGo: true, onSubmit: { Task { await unlockWithPassword() } },
                fontSize: Platform.isMac ? 15 : 17, identifier: "lock.password")
            .labelsHidden()
            .textFieldStyle(.plain)
            #if os(macOS)
            // The accent ring below replaces the system focus ring.
            .focusEffectDisabled()
            #endif
            .disabled(unlocking || lockedOut)
            .privacySensitive()
            .accessibilityIdentifier("lock.password")
            Button {
                revealed.toggle()
                fieldFocused = true
            } label: {
                Image(systemName: revealed ? "eye.slash" : "eye")
                    .font(.system(size: Platform.isMac ? 14 : 17))
                    .foregroundStyle(.secondary)
                    .frame(width: 32, height: Self.fieldHeight)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .visionHoverEffect()
            .accessibilityLabel(revealed ? Text("lock.hidePassword") : Text("lock.showPassword"))
            .accessibilityIdentifier("lock.reveal")
            // One trailing slot: Touch ID (Face ID, Optic ID) while the field is empty, the
            // arrow once something is typed. Everything lives in the one field.
            if biometrics, password.isEmpty {
                Divider().frame(height: Platform.isMac ? 18 : 22).padding(.horizontal, 2)
                fieldBiometricButton
            } else {
                unlockButton
            }
        }
        .padding(.leading, 14)
        .padding(.trailing, 6)
        .frame(height: Self.fieldHeight)
        .background {
            #if os(iOS)
            shape.fill(Color(uiColor: .secondarySystemGroupedBackground))
            #elseif os(visionOS)
            shape.fill(.fill.tertiary)
            #else
            shape.fill(.background.opacity(0.8))
            #endif
        }
        .overlay {
            shape.strokeBorder(Color.primary.opacity(ring == .clear ? 0.14 : 0), lineWidth: 1)
        }
        .overlay {
            // Focus (accent) or error (red) ring, drawn just outside the field.
            RoundedRectangle(cornerRadius: (Platform.isMac ? 10 : 14) + 3, style: .continuous)
                .strokeBorder(ring.opacity(0.35), lineWidth: 3.5)
                .padding(-3.5)
                .allowsHitTesting(false)
        }
        .overlay {
            shape.strokeBorder(ring, lineWidth: ring == .clear ? 0 : 1)
                .allowsHitTesting(false)
        }
        .modifier(Shake(amount: reduceMotion ? 0 : 7, animatableData: CGFloat(refusals)))
        .animation(.smooth(duration: 0.15), value: fieldFocused)
    }

    @ViewBuilder private var status: some View {
        if session.passwordChangedElsewhere, message == nil {
            Text("lock.masterPasswordChangedOn")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.top, 8)
                .accessibilityIdentifier("lock.passwordChangedElsewhere")
        }
        if message == nil, model.biometricOfferDue {
            // Face ID is not set up on this device yet: it needs one password unlock first.
            Label(
                "Déverrouille une fois avec ton mot de passe : OnePass te proposera \(OnboardingModel.biometryName).",
                systemImage: "faceid")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.top, 10)
                .accessibilityIdentifier("lock.biometricsHint")
        }
        if let message {
            Text(message)
                .font(.footnote)
                .foregroundStyle(.red)
                .multilineTextAlignment(.center)
                .padding(.top, 8)
                .transition(.opacity)
                .accessibilityIdentifier("lock.error")
        }
        // Sharing plan 4: recovery with the organizer's help. Shown once this device has its keys
        // (device keys plan); until then the flow cannot start.
        if model.deviceKeys != nil {
            Button("recovery.lost") { recovering = true }
                .font(.footnote)
                .padding(.top, 10)
                .accessibilityIdentifier("lock.recoverWithHelp")
                .sheet(isPresented: $recovering) { RecoverWithHelpView() }
        }
        if let until = lockoutUntil {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                let remaining = max(0, Int(until.timeIntervalSince(context.date).rounded(.up)))
                Text(remaining > 0
                     ? String(localized: "lock.tooManyAttemptsTry \(Self.duration(remaining))")
                     : String(localized: "lock.canTryAgain"))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.top, 8)
        }
    }

    // MARK: - Actions

    /// Touch ID inside the field, after a thin divider; its help text says when the password is due.
    private var fieldBiometricButton: some View {
        Button {
            Task { await unlockWithBiometrics(automatic: false) }
        } label: {
            Group {
                if unlocking {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: OnboardingModel.biometrySymbol)
                        .font(.system(size: Platform.isMac ? 18 : 22, weight: .regular))
                        .foregroundStyle(Theme.accent)
                }
            }
            .frame(width: Platform.isMac ? 32 : 40, height: Self.fieldHeight)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .visionHoverEffect()
        .disabled(unlocking)
        .help(passwordDueText ?? String(localized: "Déverrouiller avec \(OnboardingModel.biometryName)"))
        .accessibilityLabel(Text("Déverrouiller avec \(OnboardingModel.biometryName)"))
        .accessibilityIdentifier("lock.biometrics")
    }

    private var passwordDueText: String? {
        guard let days = daysUntilPassword else { return nil }
        return days <= 1
            ? String(localized: "lock.masterPasswordRequiredAgain")
            : String(localized: "lock.masterPasswordRequiredAgain \(days)")
    }

    /// The arrow at the end of the field: dim until something is typed, a spinner while unlocking.
    private var unlockButton: some View {
        let ready = !password.isEmpty && !unlocking && !lockedOut
        return Button {
            Task { await unlockWithPassword() }
        } label: {
            Group {
                if unlocking {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "arrow.right.circle.fill")
                        .font(.system(size: Platform.isMac ? 22 : 28))
                        .symbolRenderingMode(.hierarchical)
                        .foregroundStyle(ready ? Theme.accent : Color.secondary.opacity(0.5))
                }
            }
            .frame(width: Platform.isMac ? 30 : 40, height: Self.fieldHeight)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .visionHoverEffect()
        .keyboardShortcut(.defaultAction)
        .disabled(!ready)
        .animation(.smooth(duration: 0.15), value: ready)
        .accessibilityLabel(Text("common.unlock"))
        .accessibilityIdentifier("lock.unlock")
    }

    // MARK: - State

    private var lockoutUntil: Date? {
        _ = lockoutRefresh
        guard let until = model.settings.lockoutUntil, until > Date() else { return nil }
        return until
    }

    private var lockedOut: Bool { lockoutUntil != nil }

    /// Only shown when biometric unlock is on: the date the password is asked again.
    private var daysUntilPassword: Int? {
        guard session.canUseBiometrics, let accountID = model.settings.accountID,
            let due = session.environment.biometrics.passwordDueDate(accountID: accountID),
            due > Date()
        else { return nil }
        return max(1, Int((due.timeIntervalSinceNow / 86400).rounded(.up)))
    }

    private static func duration(_ seconds: Int) -> String {
        seconds < 60 ? "\(seconds) s" : "\(seconds / 60) min \(String(format: "%02d", seconds % 60)) s"
    }

    // MARK: - Unlock

    /// The password is passed as typed, never trimmed (the core normalizes it). The field is emptied
    /// on submission, before the check runs, so the view state never outlives it (success or not);
    /// the password goes into a wipeable buffer at once and crosses the FFI as bytes (the field's own
    /// `String` cannot be wiped, R5). After the first password unlock where biometrics could be on,
    /// the app offers them once (`AppModel`): the offer keeps its own wipeable copy until answered.
    /// The offer is decided after the unlock: when the session enrolled again on its own (biometrics
    /// wanted, enrollment dropped by a reboot or the 14 days), nothing is asked.
    private func unlockWithPassword() async {
        guard !password.isEmpty, !unlocking, !lockedOut else { return }
        message = nil
        let typed = SecretBytes(utf8: password)
        password = ""
        // The keyboard leaves with the submission. Left on, the field (disabled while unlocking)
        // took the keyboard back once enabled again, under the vault door: the panels parted
        // with it up and it stayed over the vault. A refusal gives the focus back below.
        fieldFocused = false
        defer { typed.wipe() }
        do {
            try await session.unlock(password: typed)
            if model.biometricOfferDue {
                model.offerBiometrics(password: typed.withUnsafeBytes { SecretBytes(copying: $0) })
            }
        } catch {
            let failure = VaultError(error)
            switch failure {
            case .wrongPassword:
                let count = model.settings.failedUnlocks
                message = count > 1
                    ? String(localized: "lock.wrongPasswordAttempts \(count)")
                    : String(localized: "lock.incorrectPassword")
                withAnimation(.linear(duration: 0.42)) { refusals += 1 }
            case .lockedOut:
                message = nil
            default:
                message = failure.localizedMessage
            }
            fieldFocused = true
        }
    }

    /// Any refusal (cancel, reboot, 14 days, biometry change) leaves the password field. Nothing
    /// asks again on its own after this (`BiometricAutoPrompt.promptStarted`). The dial is worked for
    /// the whole check (the system prompt, then the vault opening): on success it hands over to the
    /// door's quarter turn where it stands, so nothing pauses between the two.
    private func unlockWithBiometrics(automatic: Bool) async {
        guard session.canUseBiometrics, !unlocking, !biometricCheck else {
            if automatic, !biometricCheck { fieldFocused = true }
            return
        }
        message = nil
        fieldFocused = false
        biometricCheck = true
        model.biometricPromptStarted()
        do {
            try await session.unlockWithBiometrics()
            biometricCheck = false
            model.biometricPromptEnded()
        } catch {
            biometricCheck = false
            model.biometricPromptEnded()
            withAnimation(.linear(duration: 0.5)) { dialRefusals += 1 }
            fieldFocused = true
        }
    }
}

/// What the automatic try waits on: a new lock presentation, or the screen becoming visible and
/// active.
private struct AutoAttempt: Hashable {
    let presentation: UInt64
    let ready: Bool
}

#if DEBUG && os(iOS)
extension LockView {
    /// `-OnePassDemoVaultPassage YES` (captures, demo data): a staged refusal (the dial's jiggle
    /// only, no session call), then a real biometric unlock through the session, which opens the
    /// vault door. Returns whether it played.
    private func playDemoVaultDoor() async -> Bool {
        guard UserDefaults.standard.bool(forKey: "OnePassDemoVaultPassage"), DemoData.requested else {
            return false
        }
        try? await Task.sleep(for: .seconds(1.2))
        withAnimation(.linear(duration: 0.5)) { dialRefusals += 1 }
        try? await Task.sleep(for: .seconds(1.4))
        await unlockWithBiometrics(automatic: false)
        return true
    }
}
#endif

/// Horizontal shake, three swings per refusal.
private struct Shake: GeometryEffect {
    var amount: CGFloat
    var animatableData: CGFloat

    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(translationX: amount * sin(animatableData * .pi * 6), y: 0))
    }
}
