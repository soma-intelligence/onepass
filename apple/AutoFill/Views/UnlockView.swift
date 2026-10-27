import DesignKit
import LocalAuthentication
import SwiftUI
import VaultKit

/// "Déverrouiller OnePass", with the rules of the app's lock screen: glyph, ONE master password field
/// (show or hide button, then the biometric button behind a thin divider), "Déverrouiller" once
/// something is typed, Return unlocks. The Secret Key is never asked: it stays in the keychain. The
/// model tries Face ID / Touch ID once when this screen shows up (ruling A2); the field takes the
/// focus only when no such attempt runs, or once it failed or was cancelled. Like the app's lock
/// screen, the field has no password content type, so the system never offers to save it.
struct UnlockView: View {
    let model: AutoFillModel
    let session: VaultSession

    @State private var password = ""
    @State private var revealed = false
    @State private var busy = false
    @State private var message: String?
    @State private var lockoutRefresh = 0
    @FocusState private var fieldFocused: Bool

    private var unlocking: Bool { busy || session.state == .unlocking }
    private var settings: VaultSettings { session.environment.settings }

    var body: some View {
        AutoFillScaffold(title: Text(verbatim: ""), model: model) {
            ScrollView {
                VStack(spacing: 16) {
                    AppGlyph(size: 84)
                    Text("Déverrouiller OnePass")
                        .font(.title2.weight(.semibold))
                        .multilineTextAlignment(.center)
                        .padding(.top, 6)
                    passwordField
                        .padding(.top, 4)
                    if !password.isEmpty || unlocking {
                        unlockButton
                            .transition(.opacity)
                    }
                }
                .animation(.smooth(duration: 0.2), value: password.isEmpty)
                .frame(maxWidth: 334)
                .padding(.horizontal, 28)
                .padding(.vertical, 32)
                .frame(maxWidth: .infinity)
            }
            .scrollBounceBehavior(.basedOnSize)
            .background(background)
        }
        .task {
            // No automatic biometric attempt: the keyboard comes up at once.
            if !session.canUseBiometrics { fieldFocused = true }
        }
        .onChange(of: session.state) { old, new in
            // The automatic attempt failed or was cancelled: back to the password.
            if old == .unlocking, new == .locked { fieldFocused = true }
        }
        .task(id: lockoutUntil) {
            // Re-renders when the wait ends so the field and the button come back.
            guard let until = lockoutUntil else { return }
            try? await Task.sleep(for: .seconds(max(0, until.timeIntervalSinceNow) + 0.2))
            lockoutRefresh &+= 1
        }
    }

    private var background: some View {
        #if os(iOS)
        Color(uiColor: .systemGroupedBackground).ignoresSafeArea()
        #else
        Color.clear
        #endif
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
                .accessibilityIdentifier("autofill.password")
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
                .accessibilityLabel(revealed ? Text("Masquer le mot de passe") : Text("Afficher le mot de passe"))
                .accessibilityIdentifier("autofill.reveal")
                if session.canUseBiometrics {
                    Rectangle()
                        .fill(Color.primary.opacity(0.15))
                        .frame(width: 1, height: 24)
                        .padding(.horizontal, 4)
                        .accessibilityHidden(true)
                    Button {
                        Task { await unlockWithBiometrics() }
                    } label: {
                        Image(systemName: Self.biometryName == "Touch ID" ? "touchid" : "faceid")
                            .font(.system(size: 24))
                            .foregroundStyle(Theme.accent)
                            .frame(width: 40, height: 40)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .disabled(unlocking)
                    .accessibilityLabel(Text("Déverrouiller avec \(Self.biometryName)"))
                    .accessibilityIdentifier("autofill.biometrics")
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
                #else
                shape.fill(.background)
                    .overlay(shape.strokeBorder(message == nil ? Color.primary.opacity(0.15) : .red, lineWidth: 1))
                #endif
            }
            if let message {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("autofill.error")
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
            .frame(height: 36)
        }
        .buttonStyle(.glassProminent)
        .buttonBorderShape(.capsule)
        .controlSize(.large)
        .keyboardShortcut(.defaultAction)
        .disabled(password.isEmpty || unlocking || lockedOut)
        .accessibilityIdentifier("autofill.unlock")
    }

    // MARK: - State

    private var lockoutUntil: Date? {
        _ = lockoutRefresh
        guard let until = settings.lockoutUntil, until > Date() else { return nil }
        return until
    }

    private var lockedOut: Bool { lockoutUntil != nil }

    private static func duration(_ seconds: Int) -> String {
        seconds < 60 ? "\(seconds) s" : "\(seconds / 60) min \(String(format: "%02d", seconds % 60)) s"
    }

    /// The name shown on the biometric button.
    private static let biometryName: String = {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch context.biometryType {
        case .faceID: return "Face ID"
        case .opticID: return "Optic ID"
        case .touchID: return "Touch ID"
        default:
            #if os(macOS)
            return "Touch ID"
            #else
            return "Face ID"
            #endif
        }
    }()

    // MARK: - Actions

    /// The password is passed as typed, never trimmed (the core normalizes it). Success moves the
    /// model to the request's screen; a failure stays here with the session's error. The field is
    /// emptied on submission and the password goes into a wipeable buffer at once, crossing the FFI
    /// as bytes (the field's own `String` cannot be wiped, R5).
    private func unlockWithPassword() async {
        guard !password.isEmpty, !unlocking, !lockedOut else { return }
        message = nil
        busy = true
        session.lastError = nil
        let typed = SecretBytes(utf8: password)
        password = ""
        defer { typed.wipe() }
        await model.unlock(password: typed)
        busy = false
        guard model.screen == .locked else { return }
        switch session.lastError {
        case .wrongPassword?:
            let count = settings.failedUnlocks
            message = count > 1
                ? String(localized: "Mot de passe incorrect (\(count) essais).")
                : String(localized: "Mot de passe incorrect.")
        case .lockedOut?, .passwordRequired?, nil:
            message = nil
        case let failure?:
            message = failure.localizedMessage
        }
        fieldFocused = true
    }

    /// Any refusal (cancel, reboot, 14 days, biometry change) leaves the password field.
    private func unlockWithBiometrics() async {
        guard !unlocking else { return }
        message = nil
        busy = true
        await model.unlockWithBiometrics()
        busy = false
        if model.screen == .locked { fieldFocused = true }
    }
}
