import DesignKit
import SwiftUI
import VaultKit

/// Lock screen (mockup `PhoneLock`): the app glyph straddling a separator line (horizontal on iPhone
/// and iPad, the sidebar edge on Mac), the account badge, ONE master password field (show or hide
/// button, then the biometric button behind a thin divider) and "Déverrouiller" once something is
/// typed. Return unlocks. The Secret Key is never asked here: it stays in this device's keychain.
/// Biometric unlock is tried once automatically when the screen shows up in an active scene.
struct LockView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase
    @State private var password = ""
    @State private var revealed = false
    @State private var message: String?
    @State private var lockoutRefresh = 0
    @FocusState private var fieldFocused: Bool

    private var session: VaultSession { model.session }
    private var unlocking: Bool { session.state == .unlocking }

    static let glyphSize: CGFloat = 104
    #if os(macOS)
    static let sidebarWidth: CGFloat = 236
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
            guard scenePhase == .active, model.takeAutomaticBiometricAttempt() else { return }
            await unlockWithBiometrics(automatic: true)
        }
        .onAppear { fieldFocused = true }
    }

    #if os(macOS)
    /// Mac: a sidebar-wide panel on the left; the glyph sits on its edge, the form is centered in
    /// the rest of the window.
    private var layout: some View {
        GeometryReader { geometry in
            ZStack(alignment: .topLeading) {
                Rectangle()
                    .fill(Color.primary.opacity(0.035))
                    .frame(width: Self.sidebarWidth)
                    .frame(maxHeight: .infinity)
                    .ignoresSafeArea()
                Rectangle()
                    .fill(Color.primary.opacity(0.1))
                    .frame(width: 1)
                    .frame(maxHeight: .infinity)
                    .offset(x: Self.sidebarWidth)
                    .ignoresSafeArea()
                AppGlyph(size: Self.glyphSize)
                    .position(x: Self.sidebarWidth + 0.5, y: geometry.size.height / 2)
                form
                    .frame(maxWidth: 334)
                    .padding(.horizontal, 28)
                    .frame(
                        width: max(0, geometry.size.width - Self.sidebarWidth - Self.glyphSize / 2),
                        height: geometry.size.height)
                    .offset(x: Self.sidebarWidth + Self.glyphSize / 2)
            }
        }
    }
    #else
    /// iPhone, iPad and Vision Pro: the glyph on a full-width line, the form below, all centered.
    private var layout: some View {
        GeometryReader { geometry in
            ScrollView {
                VStack(spacing: 16) {
                    AppGlyph(size: Self.glyphSize)
                        .background {
                            Rectangle()
                                .fill(Color.primary.opacity(0.12))
                                .frame(width: max(geometry.size.width, 1) * 2, height: 1)
                                .accessibilityHidden(true)
                        }
                    form
                }
                .frame(maxWidth: 334)
                .padding(.horizontal, 28)
                .padding(.vertical, 40)
                #if os(visionOS)
                .glassBackgroundEffect()
                #endif
                .frame(maxWidth: .infinity, minHeight: geometry.size.height)
            }
            .scrollBounceBehavior(.basedOnSize)
            .clipped()
        }
    }
    #endif

    private var form: some View {
        VStack(spacing: 16) {
            badge
                .padding(.top, 10)
            passwordField
                .padding(.top, 4)
            if !password.isEmpty || unlocking {
                unlockButton
                    .transition(.opacity)
            }
            footer
        }
        .animation(.smooth(duration: 0.2), value: password.isEmpty)
    }

    private var background: some View {
        #if os(iOS)
        Color(uiColor: .systemGroupedBackground).ignoresSafeArea()
        #elseif os(visionOS)
        // The window carries the system glass: no opaque background.
        Color.clear
        #else
        Color.clear.background(.background)
        #endif
    }

    @ViewBuilder private var badge: some View {
        let initials = model.initials
        RoundedRectangle(cornerRadius: 14, style: .continuous)
            .fill(Theme.accent)
            .frame(width: 58, height: 58)
            .overlay {
                if initials.isEmpty {
                    Image(systemName: "person.fill").font(.system(size: 24)).foregroundStyle(.white)
                } else {
                    Text(verbatim: initials)
                        .font(.system(size: 20, weight: .semibold))
                        .foregroundStyle(.white)
                }
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(
                model.settings.displayName.isEmpty ? Text("Compte OnePass") : Text(verbatim: model.settings.displayName))
    }

    private var passwordField: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 4) {
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
                .font(.system(size: 17))
                .focused($fieldFocused)
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
                        .font(.system(size: 17))
                        .foregroundStyle(.secondary)
                        .frame(width: 32, height: 40)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .visionHoverEffect()
                .accessibilityLabel(revealed ? Text("Masquer le mot de passe") : Text("Afficher le mot de passe"))
                .accessibilityIdentifier("lock.reveal")
                if session.canUseBiometrics {
                    Rectangle()
                        .fill(Color.primary.opacity(0.15))
                        .frame(width: 1, height: 24)
                        .padding(.horizontal, 4)
                        .accessibilityHidden(true)
                    Button {
                        Task { await unlockWithBiometrics(automatic: false) }
                    } label: {
                        Image(systemName: OnboardingModel.biometrySymbol)
                            .font(.system(size: 24))
                            .foregroundStyle(Theme.accent)
                            .frame(width: 40, height: 40)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .visionHoverEffect()
                    .disabled(unlocking)
                    .accessibilityLabel(Text("Déverrouiller avec \(OnboardingModel.biometryName)"))
                    .accessibilityIdentifier("lock.biometrics")
                }
            }
            .padding(.leading, 16)
            .padding(.trailing, 8)
            .frame(height: 50)
            .background {
                let shape = RoundedRectangle(cornerRadius: 14, style: .continuous)
                #if os(iOS)
                shape.fill(Color(uiColor: .secondarySystemGroupedBackground))
                    .overlay(shape.strokeBorder(message == nil ? Color.primary.opacity(0.12) : .red, lineWidth: 1))
                #elseif os(visionOS)
                shape.fill(.fill.tertiary)
                    .overlay(shape.strokeBorder(message == nil ? Color.primary.opacity(0.12) : .red, lineWidth: 1))
                #else
                shape.fill(.background)
                    .overlay(shape.strokeBorder(message == nil ? Color.primary.opacity(0.15) : .red, lineWidth: 1))
                #endif
            }
            if let message {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.red)
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
                }
            }
        }
    }

    private var unlockButton: some View {
        Button {
            Task { await unlockWithPassword() }
        } label: {
            Group {
                if unlocking {
                    ProgressView()
                } else {
                    Text("Déverrouiller")
                }
            }
            .font(.system(size: 17, weight: .semibold))
            .frame(maxWidth: .infinity)
            .frame(height: Platform.isMac ? 30 : 36)
        }
        .buttonStyle(.glassProminent)
        .buttonBorderShape(.capsule)
        .controlSize(.large)
        .keyboardShortcut(.defaultAction)
        .disabled(password.isEmpty || unlocking || lockedOut)
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
                .padding(.horizontal, 12)
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

    // MARK: - Actions

    /// The password is passed as typed, never trimmed (the core normalizes it).
    private func unlockWithPassword() async {
        guard !password.isEmpty, !unlocking, !lockedOut else { return }
        message = nil
        do {
            try await session.unlock(password: password)
            password = ""
        } catch {
            let failure = VaultError(error)
            switch failure {
            case .wrongPassword:
                let count = model.settings.failedUnlocks
                message = count > 1
                    ? String(localized: "Mot de passe incorrect (\(count) essais).")
                    : String(localized: "Mot de passe incorrect.")
            case .lockedOut:
                message = nil
            default:
                message = failure.localizedMessage
            }
            password = ""
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
