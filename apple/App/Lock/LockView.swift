import DesignKit
import SwiftUI
import VaultKit

/// Lock screen: one centered column (on the window's glass on Mac): the app glyph, "Déverrouille
/// OnePass", the account (badge and name), ONE master password field (show or hide button, accent
/// focus ring, shakes on a wrong password) and below it the main action: "Déverrouiller avec
/// Touch ID" (Face ID, Optic ID) while the field is empty and biometric unlock is on, otherwise
/// "Déverrouiller". Return unlocks. The Secret Key is never asked here: it stays in this device's
/// keychain. Biometric unlock is tried once automatically when the screen shows up in an active scene.
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
    @FocusState private var fieldFocused: Bool

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
        .task(id: scenePhase == .active) {
            // One automatic try per app activation (AppModel), not per window or per redraw.
            // The password field takes the focus (and the keyboard comes up) only when no automatic
            // biometric attempt runs, or once it failed or was cancelled.
            guard scenePhase == .active else { return }
            if model.takeAutomaticBiometricAttempt(), session.canUseBiometrics {
                await unlockWithBiometrics(automatic: true)
            } else {
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
            AppGlyph(size: Self.glyphSize)
            Text("Déverrouille OnePass")
                .font(.system(size: Platform.isMac ? 22 : 26, weight: .semibold))
                .multilineTextAlignment(.center)
                .padding(.top, 20)
                .accessibilityAddTraits(.isHeader)
            account
                .padding(.top, 10)
            passwordField
                .padding(.top, 26)
            status
            actions
                .padding(.top, 14)
            footer
                .padding(.top, 18)
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

    @ViewBuilder private var account: some View {
        let initials = model.initials
        let name = model.settings.displayName
        HStack(spacing: 8) {
            Circle()
                .fill(Theme.accent)
                .frame(width: 24, height: 24)
                .overlay {
                    if initials.isEmpty {
                        Image(systemName: "person.fill").font(.system(size: 11)).foregroundStyle(.white)
                    } else {
                        Text(verbatim: initials)
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(.white)
                    }
                }
            Group {
                if name.isEmpty {
                    Text("Compte OnePass")
                } else {
                    Text(verbatim: name)
                }
            }
            .font(.subheadline.weight(.medium))
            .foregroundStyle(.secondary)
            .lineLimit(1)
        }
        .padding(.leading, 4)
        .padding(.trailing, 12)
        .padding(.vertical, 4)
        .background(Capsule().fill(Color.primary.opacity(0.06)))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(name.isEmpty ? Text("Compte OnePass") : Text(verbatim: name))
        .accessibilityIdentifier("lock.account")
    }

    // MARK: - Password

    private var passwordField: some View {
        let shape = RoundedRectangle(cornerRadius: Platform.isMac ? 10 : 14, style: .continuous)
        let ring: Color = message != nil ? .red : (fieldFocused ? Theme.accent : .clear)
        return HStack(spacing: 4) {
            Group {
                if revealed {
                    TextField("Mot de passe maître", text: $password, prompt: Text("Mot de passe maître"))
                        .autocorrectionDisabled()
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        #endif
                } else {
                    SecureField("Mot de passe maître", text: $password, prompt: Text("Mot de passe maître"))
                }
            }
            .labelsHidden()
            .textFieldStyle(.plain)
            .font(.system(size: Platform.isMac ? 15 : 17))
            .focused($fieldFocused)
            #if os(macOS)
            // The accent ring below replaces the system focus ring.
            .focusEffectDisabled()
            #endif
            .submitLabel(.go)
            .onSubmit { Task { await unlockWithPassword() } }
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
            .accessibilityLabel(revealed ? Text("Masquer le mot de passe") : Text("Afficher le mot de passe"))
            .accessibilityIdentifier("lock.reveal")
            unlockButton
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
            Text("Ton mot de passe maître a changé sur un autre appareil. Saisis le nouveau.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.top, 8)
                .accessibilityIdentifier("lock.passwordChangedElsewhere")
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
        if let until = lockoutUntil {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                let remaining = max(0, Int(until.timeIntervalSince(context.date).rounded(.up)))
                Text(remaining > 0
                     ? String(localized: "Trop d'essais. Nouvel essai possible dans \(Self.duration(remaining)).")
                     : String(localized: "Tu peux réessayer."))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.top, 8)
        }
    }

    // MARK: - Actions

    /// Unlocking with the password lives in the field (its arrow, or Return). Below it, only
    /// biometrics: the big button while the field is empty, a link once something is typed.
    @ViewBuilder private var actions: some View {
        VStack(spacing: 10) {
            if biometrics, password.isEmpty {
                biometricButton
            } else {
                if biometrics {
                    Button {
                        Task { await unlockWithBiometrics(automatic: false) }
                    } label: {
                        Label("Utiliser \(OnboardingModel.biometryName)", systemImage: OnboardingModel.biometrySymbol)
                            .font(.subheadline.weight(.medium))
                            .foregroundStyle(Theme.accent)
                            .padding(.vertical, 4)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .visionHoverEffect()
                    .disabled(unlocking)
                    .accessibilityLabel(Text("Déverrouiller avec \(OnboardingModel.biometryName)"))
                    .accessibilityIdentifier("lock.biometrics")
                }
            }
        }
    }

    private var biometricButton: some View {
        Button {
            Task { await unlockWithBiometrics(automatic: false) }
        } label: {
            Group {
                if unlocking {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Déverrouiller avec \(OnboardingModel.biometryName)", systemImage: OnboardingModel.biometrySymbol)
                }
            }
            .font(.system(size: Platform.isMac ? 14 : 17, weight: .semibold))
            .frame(maxWidth: .infinity)
            .frame(height: Self.buttonHeight)
        }
        .buttonStyle(.glassProminent)
        .buttonBorderShape(.capsule)
        .controlSize(.large)
        .disabled(unlocking)
        .accessibilityLabel(Text("Déverrouiller avec \(OnboardingModel.biometryName)"))
        .accessibilityIdentifier("lock.biometrics")
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
        .accessibilityLabel(Text("Déverrouiller"))
        .accessibilityIdentifier("lock.unlock")
    }

    @ViewBuilder private var footer: some View {
        if let days = daysUntilPassword {
            Text(days <= 1
                 ? String(localized: "Mot de passe maître redemandé dans 1 jour, puis tous les 14 jours.")
                 : String(localized: "Mot de passe maître redemandé dans \(days) jours, puis tous les 14 jours."))
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 8)
                .accessibilityIdentifier("lock.passwordDue")
        }
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
    private func unlockWithPassword() async {
        guard !password.isEmpty, !unlocking, !lockedOut else { return }
        message = nil
        let typed = SecretBytes(utf8: password)
        password = ""
        defer { typed.wipe() }
        let offer = model.biometricOfferDue
        do {
            try await session.unlock(password: typed)
            if offer { model.offerBiometrics(password: typed.withUnsafeBytes { SecretBytes(copying: $0) }) }
        } catch {
            let failure = VaultError(error)
            switch failure {
            case .wrongPassword:
                let count = model.settings.failedUnlocks
                message = count > 1
                    ? String(localized: "Mot de passe incorrect (\(count) essais).")
                    : String(localized: "Mot de passe incorrect.")
                withAnimation(.linear(duration: 0.42)) { refusals += 1 }
            case .lockedOut:
                message = nil
            default:
                message = failure.localizedMessage
            }
            fieldFocused = true
        }
    }

    /// Any refusal (cancel, reboot, 14 days, biometry change) leaves the password field.
    private func unlockWithBiometrics(automatic: Bool) async {
        guard session.canUseBiometrics, !unlocking else {
            if automatic { fieldFocused = true }
            return
        }
        message = nil
        do {
            try await session.unlockWithBiometrics()
        } catch {
            fieldFocused = true
        }
    }
}

/// Horizontal shake, three swings per refusal.
private struct Shake: GeometryEffect {
    var amount: CGFloat
    var animatableData: CGFloat

    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(translationX: amount * sin(animatableData * .pi * 6), y: 0))
    }
}
