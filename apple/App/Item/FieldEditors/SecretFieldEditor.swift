import DesignKit
import SwiftUI
import VaultKit

/// Concealed, password, one-time code and recovery phrase fields: a secure field with Révéler.
/// Password: "Générer" (generator sheet) and the strength meter. OTP: a base32 secret or an
/// `otpauth://` URI, with a live preview of the code. Masked again after 30 s and when it goes away.
struct SecretFieldEditor: View {
    let field: FfiField
    @Binding var value: FfiFieldValue
    @State private var revealed = false
    @State private var generating = false

    private var text: Binding<String> {
        Binding(get: { value.text }, set: { value = .fromText($0, kind: field.kind) })
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                input
                    .font(.body.monospaced())
                    .fieldInput(field.kind)
                    .accessibilityIdentifier("editor.field.\(field.id)")
                Button {
                    revealed.toggle()
                } label: {
                    Image(systemName: revealed ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(revealed ? Text("Masquer") : Text("Révéler"))
                if field.kind == .password {
                    Button {
                        generating = true
                    } label: {
                        Image(systemName: "wand.and.stars")
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(Text("Générer"))
                    .accessibilityIdentifier("editor.generate.\(field.id)")
                }
            }
            if field.kind == .password, !value.text.isEmpty {
                StrengthMeter(bits: PasswordStrength.estimatedBits(value.text))
            }
            if field.kind == .otp, !value.text.isEmpty {
                TotpCodeView(secret: value.text, compact: true)
            }
        }
        .task(id: revealed) {
            guard revealed else { return }
            try? await Task.sleep(for: .seconds(30))
            if !Task.isCancelled { revealed = false }
        }
        .onDisappear { revealed = false }
        .sheet(isPresented: $generating) {
            GeneratorSheet { generated in
                value = .password(value: generated)
            }
        }
    }

    @ViewBuilder private var input: some View {
        if revealed {
            TextField(field.label, text: text, axis: field.kind == .mnemonic ? .vertical : .horizontal)
        } else {
            SecureField(field.label, text: text)
        }
    }
}

/// SSH key: the private key is pasted (masked); the public key and the fingerprint are shown when
/// present. Generation comes later (milestone 7).
struct SshKeyEditor: View {
    let field: FfiField
    @Binding var value: FfiFieldValue
    @State private var revealed = false

    private var key: FfiSshKey? {
        if case .sshKey(let key) = value { key } else { nil }
    }

    private var privateKey: Binding<String> {
        Binding(
            get: { key?.privatePem ?? "" },
            set: { pem in
                // A different private key: the stored public key and fingerprint no longer match.
                value = pem.isEmpty
                    ? .empty
                    : .sshKey(value: FfiSshKey(privatePem: pem, publicOpenssh: "", fingerprintSha256: ""))
            })
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top) {
                Group {
                    if revealed {
                        TextField("Clé privée", text: privateKey, axis: .vertical).lineLimit(3...8)
                    } else {
                        SecureField("Clé privée (coller)", text: privateKey)
                    }
                }
                .font(.footnote.monospaced())
                .fieldInput(.concealed)
                .accessibilityIdentifier("editor.field.\(field.id)")
                Button {
                    revealed.toggle()
                } label: {
                    Image(systemName: revealed ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(revealed ? Text("Masquer") : Text("Révéler"))
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
        .onDisappear { revealed = false }
    }
}
