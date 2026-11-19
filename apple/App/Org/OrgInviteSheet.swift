import SwiftUI
import VaultKit

/// "Invite someone" on a console device: who it is for, the organisation's domain (optional, it lets
/// the new member's device check the organisation through DNS), then the link to send. Creating the
/// link signs a roster edit (R4), so it asks for presence like any change.
struct OrgInviteSheet: View {
    let org: OrgSession
    let settings: VaultSettings

    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var label = ""
    @State private var domain = ""
    @State private var link: FfiInviteLink?
    @State private var busy = false
    @State private var errorMessage: String?
    @State private var askPassword = false

    var body: some View {
        NavigationStack {
            Form {
                if let link {
                    made(link)
                } else {
                    form
                }
            }
            .formStyle(.grouped)
            .navigationTitle("org.invite")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                if link == nil {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("common.cancel") { dismiss() }
                            .accessibilityIdentifier("org.invite.cancel")
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("org.invite.create", action: create)
                            .disabled(trimmedLabel.isEmpty || busy)
                            .accessibilityIdentifier("org.invite.create")
                    }
                } else {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("common.done") { dismiss() }
                            .accessibilityIdentifier("org.invite.done")
                    }
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 460, minHeight: 360)
        #endif
        .interactiveDismissDisabled(busy)
        .onAppear { if domain.isEmpty { domain = settings.orgInviteDomain ?? settings.orgDomain ?? "" } }
        .sheet(isPresented: $askPassword) {
            PasswordPromptSheet(title: "org.invite", footer: "settings.confirmWithMasterPassword") { password in
                do {
                    try await make(password: password)
                } catch {
                    throw VaultError.other(OrgActionError(error).message)
                }
            }
        }
    }

    @ViewBuilder private var form: some View {
        Section {
            TextField("org.invite.label", text: $label)
                .accessibilityIdentifier("org.invite.label")
            TextField("org.invite.domain", text: $domain)
                .autocorrectionDisabled()
                #if os(iOS) || os(visionOS)
                .textInputAutocapitalization(.never)
                .keyboardType(.URL)
                #endif
                .accessibilityIdentifier("org.invite.domain")
        } footer: {
            Text("org.invite.footer")
        }
        if let errorMessage {
            Section {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
            }
        }
    }

    @ViewBuilder private func made(_ link: FfiInviteLink) -> some View {
        Section {
            Text(link.link)
                .font(.footnote.monospaced())
                .textSelection(.enabled)
                .lineLimit(6)
                .accessibilityIdentifier("org.invite.link")
            ShareLink(item: link.link) {
                Label("common.share", systemImage: "square.and.arrow.up")
            }
            Button {
                // The link carries the invitation's credential: the concealed clipboard clears it.
                model.session.copy(link.link, concealed: true)
                model.showToast(String(localized: "common.copied"))
            } label: {
                Label("common.copy", systemImage: "doc.on.doc")
            }
            .accessibilityIdentifier("org.invite.copy")
        } header: {
            Text(trimmedLabel)
        } footer: {
            Text("org.invite.footer")
        }
    }

    private var trimmedLabel: String { label.trimmingCharacters(in: .whitespacesAndNewlines) }

    private var trimmedDomain: String? {
        let value = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return value.isEmpty ? nil : value
    }

    private func create() {
        guard !trimmedLabel.isEmpty, !busy else { return }
        busy = true
        errorMessage = nil
        Task {
            defer { busy = false }
            do {
                try await make(password: nil)
            } catch {
                let failure = OrgActionError(error)
                if failure == .passwordRequired {
                    askPassword = true
                } else {
                    errorMessage = failure.message
                }
            }
        }
    }

    private func make(password: SecretBytes?) async throws {
        let domain = trimmedDomain
        link = try await org.invite(label: trimmedLabel, domain: domain, password: password)
        if let domain { settings.orgInviteDomain = domain }
    }
}
