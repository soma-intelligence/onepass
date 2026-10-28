import DesignKit
import LocalAuthentication
import SwiftUI
import VaultKit

/// "Déverrouille OnePass", in the design of the app's lock screen: glyph, title, the site asking,
/// the account, ONE master password field (show or hide button, accent focus ring) and below it the
/// main action: "Déverrouiller avec Face ID" (Touch ID, Optic ID) while the field is empty and
/// biometric unlock is on, otherwise "Déverrouiller". Return unlocks. The Secret Key is never asked:
/// it stays in the keychain. The model tries Face ID / Touch ID once when this screen shows up
/// (ruling A2); the field takes the focus only when no such attempt runs, or once it failed or was
/// cancelled. Like the app's lock screen, the field has no password content type, so the system
/// never offers to save it.
struct UnlockView: View {
    let model: AutoFillModel
    let session: VaultSession
    /// The site or app asking ("exemple.fr").
    var site: String?

    @State private var password = ""
    @State private var revealed = false
    @State private var busy = false
    @State private var message: String?
    @State private var lockoutRefresh = 0
    @FocusState private var fieldFocused: Bool

    private var unlocking: Bool { busy || session.state == .unlocking }
    private var settings: VaultSettings { session.environment.settings }
    private var biometrics: Bool { session.canUseBiometrics }

    #if os(macOS)
    private static let fieldHeight: CGFloat = 40
    private static let corner: CGFloat = 10
    #else
    private static let fieldHeight: CGFloat = 50
    private static let corner: CGFloat = 14
    #endif

    var body: some View {
        AutoFillScaffold(title: Text(verbatim: ""), model: model) {
            ScrollView {
                VStack(spacing: 0) {
                    AppGlyph(size: 72)
                    Text("Déverrouille OnePass")
                        .font(.title2.weight(.semibold))
                        .multilineTextAlignment(.center)
                        .padding(.top, 16)
                        .accessibilityAddTraits(.isHeader)
                    if let site {
                        Text("pour remplir \(site)")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .padding(.top, 4)
                    }
                    account
                        .padding(.top, 12)
                    passwordField
                        .padding(.top, 22)
                    status
                    actions
                        .padding(.top, 14)
                }
                .animation(.smooth(duration: 0.2), value: password.isEmpty)
                .animation(.smooth(duration: 0.2), value: message)
                .frame(maxWidth: 340)
                .padding(.horizontal, 24)
                .padding(.vertical, 28)
                .frame(maxWidth: .infinity)
            }
            .scrollBounceBehavior(.basedOnSize)
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

    /// The account in a capsule, as on the app's lock screen.
    @ViewBuilder private var account: some View {
        let name = settings.displayName
        let initials = name.split(whereSeparator: { $0.isWhitespace || $0 == "-" })
            .prefix(2).compactMap { $0.first.map { String($0).uppercased() } }.joined()
        HStack(spacing: 8) {
            Circle()
                .fill(Theme.accent.gradient)
                .frame(width: 24, height: 24)
                .overlay {
                    if initials.isEmpty {
                        Image(systemName: "person.fill").font(.system(size: 11)).foregroundStyle(.white)
                    } else {
                        Text(verbatim: initials).font(.system(size: 10, weight: .semibold)).foregroundStyle(.white)
                    }
                }
            Group {
                if name.isEmpty { Text("Compte OnePass") } else { Text(verbatim: name) }
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
    }

    private var passwordField: some View {
        let shape = RoundedRectangle(cornerRadius: Self.corner, style: .continuous)
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
            .font(.system(size: 17))
            .focused($fieldFocused)
            #if os(macOS)
            .focusEffectDisabled()
            #endif
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
                    #if os(iOS)
                    .contentTransition(.symbolEffect(.replace))
                    .frame(width: 44, height: Self.fieldHeight)
                    #else
                    .frame(width: 32, height: Self.fieldHeight)
                    #endif
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(revealed ? Text("Masquer le mot de passe") : Text("Afficher le mot de passe"))
            .accessibilityIdentifier("autofill.reveal")
            #if os(iOS)
            submitButton
            #endif
        }
        .padding(.leading, 14)
        .padding(.trailing, 6)
        .frame(height: Self.fieldHeight)
        .background {
            #if os(iOS)
            shape.fill(Color(uiColor: .secondarySystemGroupedBackground))
            #else
            shape.fill(.background.opacity(0.8))
            #endif
        }
        .overlay { shape.strokeBorder(Color.primary.opacity(ring == .clear ? 0.12 : 0), lineWidth: 1) }
        .overlay {
            // Focus (accent) or error (red) ring, drawn just outside the field.
            RoundedRectangle(cornerRadius: Self.corner + 3, style: .continuous)
                .strokeBorder(ring.opacity(0.35), lineWidth: 3.5)
                .padding(-3.5)
                .allowsHitTesting(false)
        }
        .overlay { shape.strokeBorder(ring, lineWidth: ring == .clear ? 0 : 1).allowsHitTesting(false) }
        .animation(.smooth(duration: 0.15), value: fieldFocused)
        #if os(iOS)
        // A refused password: the error haptic lands with the message under the field.
        .sensoryFeedback(trigger: message) { _, new in new == nil ? nil : .error }
        #endif
    }

    @ViewBuilder private var status: some View {
        if let message {
            Text(message)
                .font(.footnote)
                .foregroundStyle(.red)
                .multilineTextAlignment(.center)
                .padding(.top, 8)
                .transition(.opacity)
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
                    .multilineTextAlignment(.center)
            }
            .padding(.top, 8)
        }
    }

    #if os(iOS)
    /// iPhone: the unlock action sits at the end of the field, an arrow lit once something is
    /// typed. Return submits too.
    private var submitButton: some View {
        let enabled = !password.isEmpty && !unlocking && !lockedOut
        return Button {
            Task { await unlockWithPassword() }
        } label: {
            Group {
                if unlocking, !password.isEmpty {
                    ProgressView()
                } else {
                    Image(systemName: "arrow.right.circle.fill")
                        .font(.system(size: 28))
                        .symbolRenderingMode(.palette)
                        .foregroundStyle(.white, enabled ? Theme.accent : Color.secondary.opacity(0.35))
                }
            }
            .frame(width: 44, height: Self.fieldHeight)
            .contentShape(Rectangle())
            .animation(.easeOut(duration: 0.15), value: enabled)
        }
        .buttonStyle(PressableButtonStyle(scale: 0.9))
        .disabled(!enabled)
        .accessibilityLabel(Text("Déverrouiller"))
        .accessibilityIdentifier("autofill.unlock")
    }
    #endif

    /// Empty field with biometrics on: the biometric button leads. Something typed: "Déverrouiller"
    /// leads (on iPhone, the arrow in the field) and biometrics stay one tap away.
    @ViewBuilder private var actions: some View {
        VStack(spacing: 10) {
            if biometrics, password.isEmpty {
                AutoFillPrimaryButton {
                    Task { await unlockWithBiometrics() }
                } label: {
                    if unlocking {
                        ProgressView()
                    } else {
                        Label("Déverrouiller avec \(Self.biometryName)", systemImage: Self.biometrySymbol)
                    }
                }
                .disabled(unlocking)
                .accessibilityLabel(Text("Déverrouiller avec \(Self.biometryName)"))
                .accessibilityIdentifier("autofill.biometrics")
            } else {
                #if !os(iOS)
                // iPhone: the arrow inside the field (`submitButton`) unlocks.
                AutoFillPrimaryButton {
                    Task { await unlockWithPassword() }
                } label: {
                    if unlocking { ProgressView() } else { Text("Déverrouiller") }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || unlocking || lockedOut)
                .accessibilityIdentifier("autofill.unlock")
                #endif
                if biometrics {
                    Button {
                        Task { await unlockWithBiometrics() }
                    } label: {
                        Label("Utiliser \(Self.biometryName)", systemImage: Self.biometrySymbol)
                            .font(.subheadline.weight(.medium))
                            .foregroundStyle(Theme.accent)
                            .padding(.vertical, 4)
                            #if os(iOS)
                            .frame(minHeight: 44)
                            #endif
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .disabled(unlocking)
                    .accessibilityLabel(Text("Déverrouiller avec \(Self.biometryName)"))
                    .accessibilityIdentifier("autofill.biometrics")
                }
            }
        }
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

    private static var biometrySymbol: String {
        switch biometryName {
        case "Touch ID": "touchid"
        case "Optic ID": "opticid"
        default: "faceid"
        }
    }

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
