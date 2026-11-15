import SwiftUI
import VaultKit

/// "Join an organisation": the invitation (from a link, or pasted here), then the organisation as
/// this device pinned it (its name, its fingerprint and where the fingerprint was confirmed) and the
/// member's name. Opening an invitation already makes the managed slot and its pin
/// (`AppModel.beginOrgJoin`), so the onboarding sign up waits under the sheet; "Join" hands over to
/// it, "Cancel" (or closing the sheet any other way) takes the slot out again (`cancelOrgJoin`).
struct OrgJoinSheet: View {
    /// nil: the sheet starts with the field the link is pasted in.
    let invite: FfiOrgInvite?
    /// The name and colour chosen in "Add an account", if the sheet came from there.
    var look: OrgAccountLook? = nil

    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var phase: Phase = .paste
    @State private var link = ""
    @State private var linkInvalid = false
    @State private var name = ""
    @State private var actionError: String?
    @State private var verifying = false
    /// Outlives the view: a pin still under way when the sheet closes is undone once it returns.
    @State private var lifetime = Lifetime()

    private enum Phase: Equatable {
        case paste
        case opening
        case ready(FfiOrgState, FfiOrgInvite)
        case failed(String)
    }

    private final class Lifetime {
        var joined = false
        var closed = false
        /// The slot this sheet's `beginOrgJoin` made: the only one it may cancel.
        var slot: String?
    }

    var body: some View {
        NavigationStack {
            Form { content }
                .formStyle(.grouped)
                .navigationTitle("org.join.title")
                #if os(iOS) || os(visionOS)
                .navigationBarTitleDisplayMode(.inline)
                #endif
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("common.cancel") { dismiss() }
                            .accessibilityIdentifier("org.join.cancel")
                    }
                    ToolbarItem(placement: .confirmationAction) { confirmButton }
                }
        }
        #if os(macOS)
        .frame(minWidth: 460, minHeight: 520)
        #endif
        .task {
            guard case .paste = phase else { return }
            // The name of the account shown before the new slot takes over.
            if name.isEmpty { name = model.settings.displayName }
            if let invite { await open(invite) }
        }
        .onDisappear {
            lifetime.closed = true
            if !lifetime.joined, let slot = lifetime.slot { model.cancelOrgJoin(slot: slot) }
        }
    }

    @ViewBuilder private var content: some View {
        switch phase {
        case .paste:
            Section {
                TextField("org.join.pasteLink", text: $link, axis: .vertical)
                    .lineLimit(1...4)
                    .autocorrectionDisabled()
                    #if os(iOS) || os(visionOS)
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                    #endif
                    .onSubmit(openPasted)
                    .accessibilityIdentifier("org.join.link")
            } footer: {
                if linkInvalid {
                    Text("org.join.badLink")
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("org.join.badLink")
                }
            }
        case .opening:
            Section {
                ProgressView()
                    .frame(maxWidth: .infinity)
                    .accessibilityIdentifier("org.join.opening")
            }
        case .failed(let message):
            Section {
                Label(message, systemImage: "exclamationmark.octagon")
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("org.join.refused")
            }
        case .ready(let state, let invite):
            Section {
                Text(state.name)
                    .font(.title3.weight(.semibold))
                    .accessibilityIdentifier("org.join.orgName")
            }
            Section {
                OrgFingerprintView(words: state.fingerprintWords, source: state.source, domain: invite.domain)
                if case .tofu(verified: false) = state.source {
                    Text("org.tofu.warning")
                        .font(.footnote)
                        .accessibilityIdentifier("org.tofu.warning")
                    Button {
                        Task { await markVerified(invite) }
                    } label: {
                        Label("org.tofu.markVerified", systemImage: "checkmark.seal")
                    }
                    .disabled(verifying)
                    .accessibilityIdentifier("org.tofu.markVerified")
                }
            } header: {
                Text("org.join.fingerprint")
            }
            Section {
                TextField("org.join.yourName", text: $name)
                    .textContentType(.name)
                    .accessibilityIdentifier("org.join.name")
            } header: {
                Text("org.join.yourName")
            } footer: {
                if let actionError {
                    Text(actionError).foregroundStyle(.red)
                }
            }
        }
    }

    @ViewBuilder private var confirmButton: some View {
        switch phase {
        case .paste:
            Button("common.continue", action: openPasted)
                .disabled(link.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .accessibilityIdentifier("org.join.continue")
        case .ready:
            Button("org.join.confirm", action: join)
                .disabled(!Self.nameFits(name))
                .accessibilityIdentifier("org.join.confirm")
        case .opening, .failed:
            EmptyView()
        }
    }

    /// 1 to 64 bytes of UTF-8 once trimmed (the core's limit, R12).
    private static func nameFits(_ name: String) -> Bool {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return !trimmed.isEmpty && trimmed.utf8.count <= 64
    }

    private func openPasted() {
        let text = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        guard let parsed = try? orgInviteParse(link: text, allowLoopbackHttp: MailboxEndpoints.allowsLocalHTTP)
        else {
            linkInvalid = true
            return
        }
        linkInvalid = false
        link = ""
        Task { await open(parsed) }
    }

    /// The pin plan, the managed slot and the pin (`beginOrgJoin`). A refusal is shown; the sheet
    /// closed meanwhile takes the slot out again.
    private func open(_ invite: FfiOrgInvite) async {
        phase = .opening
        do {
            let start = try await model.beginOrgJoin(invite, look: look)
            if lifetime.closed {
                model.cancelOrgJoin(slot: start.slot)
                return
            }
            lifetime.slot = start.slot
            phase = .ready(start.state, invite)
        } catch {
            phase = .failed(error.message)
        }
    }

    private func markVerified(_ invite: FfiOrgInvite) async {
        guard let slot = lifetime.slot, model.managedOnboarding?.slot == slot, let org = model.orgSession(for: slot)
        else { return }
        verifying = true
        defer { verifying = false }
        do {
            try await org.markVerified()
            actionError = nil
            if let state = org.state { phase = .ready(state, invite) }
        } catch {
            actionError = error.message
        }
    }

    private func join() {
        guard Self.nameFits(name), let slot = lifetime.slot else { return }
        lifetime.joined = true
        model.confirmOrgJoin(slot: slot, displayName: name.trimmingCharacters(in: .whitespacesAndNewlines))
        dismiss()
    }
}
