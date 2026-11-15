import SwiftUI
import VaultKit

/// A join request on a console device: the name, the code the member reads out (it must match),
/// where the invitation came from, the devices, then Accept or Decline through `OrgConfirmSheet`.
struct OrgJoinRequestSheet: View {
    let org: OrgSession
    let request: FfiJoinRequest

    @Environment(\.dismiss) private var dismiss
    @State private var confirmation: OrgConfirmation?
    @State private var errorMessage: String?
    @State private var preparing = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(request.displayName)
                        .font(.title3.weight(.semibold))
                    OrgRequestOrigin(request: request)
                }
                Section {
                    OrgCodeWords(words: request.codeWords)
                        .accessibilityIdentifier("org.request.codeWords")
                } footer: {
                    Text("org.request.code")
                }
                Section {
                    ForEach(request.devices, id: \.fingerprint) { OrgDeviceRow(device: $0) }
                } header: {
                    Text("org.summary.devices")
                }
                Section {
                    Button("org.action.accept", action: accept)
                        .accessibilityIdentifier("org.request.accept")
                    Button("org.action.decline", role: .destructive, action: decline)
                        .accessibilityIdentifier("org.request.decline")
                }
                .disabled(preparing)
                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("org.joinRequests")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("common.cancel") { dismiss() }
                        .accessibilityIdentifier("org.request.dismiss")
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 440, minHeight: 460)
        #endif
        .sheet(item: $confirmation) { OrgConfirmSheet(confirmation: $0, completed: { dismiss() }) }
    }

    /// Active with no extra role; roles are changed afterwards from the member's page.
    private func accept() {
        let edit = FfiRosterEdit.accept(accountId: request.accountId, roles: [])
        preparing = true
        errorMessage = nil
        Task {
            defer { preparing = false }
            do {
                let summary = try await org.summary(for: edit)
                confirmation = .edit(edit, summary: summary, org: org)
            } catch {
                errorMessage = OrgActionError(error).message
            }
        }
    }

    private func decline() {
        let request = request
        confirmation = OrgConfirmation(
            title: String(localized: "org.confirm.decline \(request.displayName)"), destructive: true,
            perform: { [org] password in try await org.decline(request, password: password) })
    }
}

/// "Invited from this device", or the label of the invitation, under a join request's name.
struct OrgRequestOrigin: View {
    let request: FfiJoinRequest

    var body: some View {
        if request.issuedHere {
            Label("org.request.issuedHere", systemImage: "checkmark.circle")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        if let label = request.inviteLabel, !label.isEmpty {
            Label(label, systemImage: "tag")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
}

/// A join code: 5 words, large and monospaced, read aloud between the member and an administrator.
struct OrgCodeWords: View {
    let words: [String]

    var body: some View {
        Text(words.joined(separator: " "))
            .font(.title2.monospaced().weight(.medium))
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 4)
            .accessibilityLabel(words.joined(separator: ", "))
    }
}

extension FfiJoinRequest: @retroactive Identifiable {
    public var id: String { accountId }
}
