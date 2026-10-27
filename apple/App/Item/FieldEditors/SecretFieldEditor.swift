import DesignKit
import SwiftUI
import VaultKit

/// Concealed, password, one-time code and recovery phrase fields: a secure field with Révéler.
/// Password: "Générer" (generator sheet) and the strength meter. OTP: a base32 secret or an
/// `otpauth://` URI, with a live preview of the code. Masked again after 30 s, when it goes away, on lock,
/// when the scene leaves the foreground and while the screen is captured.
struct SecretFieldEditor: View {
    @Environment(AppModel.self) private var model
    let field: FfiField
    @Binding var value: FfiFieldValue
    @Environment(\.requestGenerator) private var requestGenerator
    @State private var revealed = false
    #if os(iOS) || os(visionOS)
    @Environment(\.isSceneCaptured) private var captured
    #else
    private let captured = false
    #endif
    @State private var generating = false
    /// The value the generator just put in, with its recipe bits (the meter shows those for it).
    @State private var generated: GeneratedValue?

    private var text: Binding<String> {
        Binding(get: { value.text }, set: { value = .fromText($0, kind: field.kind) })
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                input
                    .font(.body.monospaced())
                    .fieldInput(field.kind)
                    .privacySensitive()
                    .accessibilityIdentifier("editor.field.\(field.id)")
                // Strength as a word and a ring on the field's line, like the read view.
                if field.kind == .password, !value.text.isEmpty {
                    StrengthBadge(bits: meterBits)
                }
                Button {
                    revealed.toggle()
                } label: {
                    Image(systemName: revealed ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(revealed ? Text("Masquer") : Text("Révéler"))
                if field.kind == .password {
                    Button {
                        openGenerator()
                    } label: {
                        Image(systemName: "wand.and.stars")
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(Text("Générer"))
                    .accessibilityIdentifier("editor.generate.\(field.id)")
                }
            }
            if field.kind == .otp, !value.text.isEmpty {
                if captured {
                    Text(verbatim: FieldRow.mask).font(.callout.monospacedDigit())
                } else {
                    TotpCodeView(secret: value.text, compact: true)
                }
            }
        }
        .task(id: revealed) {
            guard revealed else { return }
            try? await Task.sleep(for: .seconds(30))
            if !Task.isCancelled { revealed = false }
        }
        .onDisappear { revealed = false }
        // Lock, or the scene left the foreground (`VaultSession.concealGeneration`).
        .onChange(of: model.session.concealGeneration) { revealed = false }
        // Screen captured (iOS, visionOS): masked now, and still masked once the capture ends.
        .onChange(of: captured) { _, now in if now { revealed = false } }
        #if DEBUG
        .task {
            if field.kind == .password, field.id == "password",
                UserDefaults.standard.bool(forKey: "OnePassDebugGenerator")
            {
                try? await Task.sleep(for: .milliseconds(600))
                openGenerator()
            }
        }
        #endif
        .sheet(isPresented: $generating) {
            GeneratorSheet(onUse: { _ in }, onUseWithBits: apply)
        }
    }

    /// Same measure as the generator: its recipe bits for the value it just generated, the shared
    /// estimate (which gives a generated value the same bits) for anything else.
    private var meterBits: Double {
        if let generated, generated.text == value.text { return generated.bits }
        return PasswordStrength.estimatedBits(value.text)
    }

    /// The editor presents the generator from its form (one click opens it: a sheet attached to a
    /// form row can be dropped while the row redraws as its field loses the focus); a local sheet
    /// elsewhere.
    private func openGenerator() {
        if let requestGenerator {
            requestGenerator(GeneratorRequest(apply: apply))
        } else {
            generating = true
        }
    }

    private func apply(_ text: String, _ bits: Double) {
        value = .password(value: text)
        generated = GeneratedValue(text: text, bits: bits)
    }

    @ViewBuilder private var input: some View {
        // The label is above the row: no placeholder repeating it inside the field.
        if revealed && !captured {
            TextField(field.displayLabel, text: text, prompt: Text(""), axis: field.kind == .mnemonic ? .vertical : .horizontal)
        } else {
            SecureField(field.displayLabel, text: text, prompt: Text(""))
        }
    }
}

private struct GeneratedValue: Equatable {
    let text: String
    let bits: Double
}

/// A field asks its editor for the generator; `apply` receives the value and its recipe bits.
struct GeneratorRequest: Identifiable {
    let id = UUID()
    let apply: @MainActor (String, Double) -> Void
}

extension EnvironmentValues {
    /// Set by the item editor: presents the generator sheet from the form itself.
    @Entry var requestGenerator: (@MainActor (GeneratorRequest) -> Void)? = nil
}


/// SSH key: the private key is pasted (masked as bullets; Révéler shows it in a monospaced
/// multi-line editor that keeps its line breaks, masked again after 30 s). The public key and the
/// fingerprint are shown when present. Generation comes later (milestone 7).
struct SshKeyEditor: View {
    @Environment(AppModel.self) private var model
    let field: FfiField
    @Binding var value: FfiFieldValue
    @State private var revealed = false
    #if os(iOS) || os(visionOS)
    @Environment(\.isSceneCaptured) private var captured
    #else
    private let captured = false
    #endif

    private var key: FfiSshKey? {
        if case .sshKey(let key) = value { key } else { nil }
    }

    private var privateKey: Binding<String> {
        Binding(
            get: { key?.privatePem ?? "" },
            set: { pem in
                guard pem != key?.privatePem else { return }
                // A different private key: the stored public key and fingerprint no longer match.
                value = pem.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    ? .empty
                    : .sshKey(value: FfiSshKey(privatePem: pem, publicOpenssh: "", fingerprintSha256: ""))
            })
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 10) {
                Group {
                    if revealed && !captured {
                        TextEditor(text: privateKey)
                            .font(.footnote.monospaced())
                            .frame(minHeight: 120)
                            .fieldInput(.concealed)
                    } else {
                        Text(privateKey.wrappedValue.isEmpty ? String(localized: "Aucune clé privée") : FieldRow.mask)
                            .font(.body.monospaced())
                            .foregroundStyle(privateKey.wrappedValue.isEmpty ? .secondary : .primary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .privacySensitive()
                .accessibilityIdentifier("editor.field.\(field.id)")
                Button {
                    revealed.toggle()
                } label: {
                    Image(systemName: revealed ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(revealed ? Text("Masquer") : Text("Révéler"))
            }
            HStack {
                PasteButton(payloadType: String.self) { strings in
                    if let pasted = strings.first { privateKey.wrappedValue = pasted }
                }
                .labelStyle(.titleAndIcon)
                if key != nil {
                    Button("Effacer", role: .destructive) { value = .empty }
                        .buttonStyle(.borderless)
                }
            }
            if let key, !key.publicOpenssh.isEmpty {
                LabeledContent("Clé publique") {
                    Text(key.publicOpenssh).font(.caption.monospaced()).lineLimit(2).truncationMode(.middle)
                }
            }
            if let key, !key.fingerprintSha256.isEmpty {
                LabeledContent("Empreinte") {
                    Text(key.fingerprintSha256).font(.caption.monospaced())
                }
            }
            Text("La génération de clés arrive au jalon 7.").font(.caption).foregroundStyle(.secondary)
        }
        .task(id: revealed) {
            guard revealed else { return }
            try? await Task.sleep(for: .seconds(30))
            if !Task.isCancelled { revealed = false }
        }
        .onDisappear { revealed = false }
        // Lock, or the scene left the foreground (`VaultSession.concealGeneration`).
        .onChange(of: model.session.concealGeneration) { revealed = false }
        // Screen captured (iOS, visionOS): masked now, and still masked once the capture ends.
        .onChange(of: captured) { _, now in if now { revealed = false } }
    }
}
