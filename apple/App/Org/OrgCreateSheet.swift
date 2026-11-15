import SwiftUI
import VaultKit

/// "Create an organisation" (Mac and iPad, `OrgConsole.isConsoleDevice`): its name, its server
/// (the device management profile's when there is one, else the hosted one) and the server's
/// invitation code for the organisation mailbox. Then the onboarding signs the creator up on a
/// managed slot; nothing reaches the server before that account exists (`beginOrgCreation`).
struct OrgCreateSheet: View {
    /// The name and colour chosen in "Add an account", if the sheet came from there.
    var look: OrgAccountLook? = nil

    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var server = ""
    @State private var serverInvite = ""
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("org.create.name", text: $name)
                        .accessibilityIdentifier("org.create.name")
                } header: {
                    Text("org.create.name")
                }
                Section {
                    TextField("org.create.server", text: $server)
                        .autocorrectionDisabled()
                        #if os(iOS) || os(visionOS)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        #endif
                        .accessibilityIdentifier("org.create.server")
                    TextField("org.create.serverInvite", text: $serverInvite)
                        .autocorrectionDisabled()
                        #if os(iOS) || os(visionOS)
                        .textInputAutocapitalization(.never)
                        #endif
                        .accessibilityIdentifier("org.create.serverInvite")
                } header: {
                    Text("org.create.server")
                } footer: {
                    VStack(alignment: .leading, spacing: 6) {
                        if let errorMessage {
                            Text(errorMessage).foregroundStyle(.red)
                        }
                        Text("org.create.footer")
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("org.create.title")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("common.cancel") { dismiss() }
                        .accessibilityIdentifier("org.create.cancel")
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("common.continue", action: create)
                        .disabled(trimmed(name).isEmpty || trimmed(server).isEmpty)
                        .accessibilityIdentifier("org.create.confirm")
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 460, minHeight: 440)
        #endif
        .onAppear {
            if server.isEmpty { server = Self.defaultServer() }
        }
    }

    /// The server the device management profile names, else the hosted one.
    static func defaultServer() -> String {
        if case .valid(let config) = ManagedOrgConfig.read() { return config.serverURL.absoluteString }
        return MailboxEndpoints.hosted()?.absoluteString ?? ""
    }

    private func trimmed(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func create() {
        guard let url = URL(string: trimmed(server)) else {
            errorMessage = AccountsError.serverUnavailable.message
            return
        }
        do {
            try model.beginOrgCreation(
                name: trimmed(name), serverURL: url, serverInvite: trimmed(serverInvite), look: look)
            dismiss()
        } catch {
            errorMessage = error.message
        }
    }
}
