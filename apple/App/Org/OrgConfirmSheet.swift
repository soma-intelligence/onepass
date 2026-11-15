import SwiftUI
import VaultKit

/// One organisation change waiting for the user's yes: what it does, as rows of "before → after"
/// built from the local summary (`OrgSession.summary(for:)`, never a fresh server answer), and the
/// call that signs it once confirmed.
struct OrgConfirmation: Identifiable {
    struct Row: Hashable {
        let label: String
        let value: String
    }

    let id = UUID()
    let title: String
    var rows: [Row] = []
    /// The core rules let this device sign it (else the sheet says so and offers nothing).
    var allowed = true
    var destructive = false
    /// Signs and sends the change. `nil`: biometrics first; the sheet asks the master password when
    /// they can't answer (`OrgActionError.passwordRequired`) and calls again with it.
    let perform: @MainActor (SecretBytes?) async throws -> Void

    /// A roster edit (`apply`), from its summary.
    @MainActor
    static func edit(_ edit: FfiRosterEdit, summary: FfiEditSummary, org: OrgSession) -> OrgConfirmation {
        let name = summary.memberName
        let devices = Int(summary.deviceCount)
        let title: String
        var destructive = false
        switch edit {
        case .accept: title = String(localized: "org.confirm.accept \(name) \(devices)")
        case .setRoles: title = String(localized: "org.confirm.roles \(name)")
        case .suspend:
            title = String(localized: "org.confirm.suspend \(name)")
            destructive = true
        case .reactivate: title = String(localized: "org.confirm.reactivate \(name)")
        case .remove:
            title = String(localized: "org.confirm.remove \(name) \(devices)")
            destructive = true
        }
        var rows: [Row] = []
        let rolesBefore = OrgText.roles(summary.rolesBefore)
        let rolesAfter = OrgText.roles(summary.rolesAfter)
        rows.append(Row(
            label: String(localized: "org.summary.roles"),
            value: rolesBefore == rolesAfter ? rolesAfter : "\(rolesBefore) → \(rolesAfter)"))
        let stateAfter = OrgText.state(summary.stateAfter)
        let stateBefore = summary.stateBefore.map(OrgText.state)
        rows.append(Row(
            label: String(localized: "org.summary.state"),
            value: stateBefore.map { $0 == stateAfter ? stateAfter : "\($0) → \(stateAfter)" } ?? stateAfter))
        rows.append(Row(
            label: String(localized: "org.summary.devices"),
            value: String(localized: "org.member.devices \(devices)")))
        return OrgConfirmation(
            title: title, rows: rows, allowed: summary.allowed, destructive: destructive,
            perform: { password in _ = try await org.apply(edit, password: password) })
    }
}

/// The confirmation sheet every organisation change goes through: the summary rows, then presence
/// (biometrics, else the master password in `PasswordPromptSheet`), then the signed change.
struct OrgConfirmSheet: View {
    let confirmation: OrgConfirmation
    /// Called once the change is made, after the sheet closes.
    var completed: () -> Void = {}

    @Environment(\.dismiss) private var dismiss
    @State private var busy = false
    @State private var errorMessage: String?
    @State private var askPassword = false
    @State private var doneWithPassword = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(confirmation.title)
                        .font(.headline)
                        .accessibilityIdentifier("org.confirm.title")
                }
                if !confirmation.rows.isEmpty {
                    Section {
                        ForEach(confirmation.rows, id: \.self) { row in
                            LabeledContent(row.label, value: row.value)
                        }
                    }
                }
                if !confirmation.allowed {
                    Section {
                        Label(OrgActionError.notAllowed.message, systemImage: "hand.raised")
                            .foregroundStyle(.red)
                    }
                }
                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("app.confirm")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("common.cancel") { dismiss() }
                        .accessibilityIdentifier("org.confirm.cancel")
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("app.confirm", role: confirmation.destructive ? .destructive : nil, action: run)
                        .disabled(!confirmation.allowed || busy)
                        .accessibilityIdentifier("org.confirm.go")
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 420, minHeight: 300)
        #endif
        .interactiveDismissDisabled(busy)
        .sheet(isPresented: $askPassword, onDismiss: passwordClosed) {
            PasswordPromptSheet(title: "app.confirm", footer: "settings.confirmWithMasterPassword") { password in
                do {
                    try await confirmation.perform(password)
                } catch {
                    throw VaultError.other(OrgActionError(error).message)
                }
                doneWithPassword = true
            }
        }
    }

    private func run() {
        guard confirmation.allowed, !busy else { return }
        busy = true
        errorMessage = nil
        Task {
            defer { busy = false }
            do {
                try await confirmation.perform(nil)
                finish()
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

    private func passwordClosed() {
        if doneWithPassword { finish() }
    }

    private func finish() {
        dismiss()
        completed()
    }
}
