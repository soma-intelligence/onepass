import DesignKit
import SwiftUI
import VaultKit

/// "Nouveau login" from the list (MACAPP-03): username (the first Identity's e-mail by default), a
/// generated password (the generator profile of the app), title and vault, then one button that
/// saves the Login and fills both fields. Pushed on the list's navigation stack: same sheet, same
/// unlock. The password stays masked unless shown.
struct NewLoginView: View {
    let model: AutoFillModel
    let session: VaultSession
    var site: String?

    @State private var title = ""
    @State private var user = ""
    @State private var password = ""
    @State private var revealed = false
    @State private var vaultID = ""
    @State private var busy = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                AutoFillLabel("views.newItemHeader")
                AutoFillCardRows {
                    AutoFillFieldRow(label: Text("views.title2")) {
                        TextField("views.title", text: $title, prompt: Text(verbatim: site ?? ""))
                            .textFieldStyle(.plain)
                            .accessibilityIdentifier("autofill.newLogin.title")
                    }
                    VaultPicker(vaults: session.vaults, selection: $vaultID)
                }
                .padding(.bottom, 10)
                AutoFillLabel("views.login")
                AutoFillCardRows {
                    AutoFillFieldRow(label: Text("views.username")) {
                        TextField("views.username", text: $user)
                            .textFieldStyle(.plain)
                            .autocorrectionDisabled()
                            #if os(iOS)
                            .textInputAutocapitalization(.never)
                            .keyboardType(.emailAddress)
                            #endif
                            .accessibilityIdentifier("autofill.newLogin.user")
                    }
                    HStack(spacing: 8) {
                        AutoFillFieldRow(label: Text("views.password")) {
                            if revealed {
                                Text(verbatim: password)
                                    .font(.body.monospaced())
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                    .privacySensitive()
                            } else {
                                Text(verbatim: FieldRow.mask).accessibilityLabel(Text("views.hidden"))
                            }
                        }
                        Button {
                            revealed.toggle()
                        } label: {
                            Image(systemName: revealed ? "eye.slash" : "eye")
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel(revealed ? Text("views.hidePassword") : Text("views.showPassword"))
                        Button {
                            regenerate()
                        } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(Theme.accent)
                        .padding(.trailing, 14)
                        .accessibilityLabel(Text("views.newPassword"))
                        .accessibilityIdentifier("autofill.newLogin.regenerate")
                    }
                }
                SessionErrorText(session: session)
                    .padding(.horizontal, 6)
                AutoFillPrimaryButton {
                    create()
                } label: {
                    if busy {
                        ProgressView()
                    } else {
                        Text("views.saveAndFill")
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(busy || !canCreate)
                .padding(.top, 14)
                .accessibilityIdentifier("autofill.newLogin.save")
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .scrollDismissesKeyboard(.interactively)
        .background(AutoFillBackground())
        .navigationTitle(Text("views.newLogin"))
        .onAppear {
            if vaultID.isEmpty { vaultID = session.vaults.first?.id ?? "" }
            if user.isEmpty { user = model.suggestedUsername ?? "" }
            if password.isEmpty { regenerate() }
        }
    }

    private var canCreate: Bool {
        !password.isEmpty && session.vaults.contains { $0.id == vaultID }
    }

    private func regenerate() {
        password = model.generatedPassword() ?? ""
    }

    private func create() {
        guard !busy, canCreate else { return }
        busy = true
        session.lastError = nil
        let (title, user, password, vaultID) = (title, user, password, vaultID)
        Task {
            await model.createLogin(title: title, user: user, password: password, vaultID: vaultID)
            busy = false
        }
    }
}
