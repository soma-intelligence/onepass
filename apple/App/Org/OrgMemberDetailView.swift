import SwiftUI
import VaultKit

/// One member of the organisation: its devices by fingerprint, its roles, and (on a console device,
/// for an account that manages members) the changes: roles, Suspend, Reactivate, Remove, "Remove
/// admin" for a former owner (R19) and "Make owner" for an owner holding the owner keys. Each change
/// goes through `OrgConfirmSheet`. Read only on an iPhone.
struct OrgMemberDetailView: View {
    let org: OrgSession
    let accountID: String

    @State private var roles: Set<FfiOrgRole> = []
    @State private var confirmation: OrgConfirmation?
    @State private var errorMessage: String?
    @State private var ownerKeys = false
    @State private var preparing = false
    @State private var retrying = false

    /// The roles a manager toggles here; Owner is shown read only, the others stay as they are.
    private static let toggled: [FfiOrgRole] = [.admin, .userManager, .policyManager, .auditor]

    private var member: FfiOrgMember? { org.state?.members.first { $0.accountId == accountID } }
    private var isMe: Bool { org.me?.accountId == accountID }
    private var isHeadOwner: Bool { org.state?.owners.contains(accountID) ?? false }

    /// Changes are made on a Mac or an iPad, by an account that manages members, never on itself.
    private var canEdit: Bool { OrgConsole.isConsoleDevice && org.canManageMembers && !isMe }

    /// The roster edit is signed but the server did not take the member's access: try again (R38 (e)).
    private func retryAccess() {
        retrying = true
        errorMessage = nil
        Task {
            defer { retrying = false }
            do {
                if try await org.retryServerAccess(accountID: accountID) == false {
                    errorMessage = String(localized: "org.access.notUpdated")
                }
            } catch {
                errorMessage = OrgActionError(error).message
            }
        }
    }

    var body: some View {
        Form {
            if let member {
                content(member)
            }
        }
        .settingsPage(LocalizedStringKey(member.map { OrgText.name(of: $0, isMe: isMe) } ?? ""))
        .onAppear { roles = Set(member?.roles ?? []) }
        .onChange(of: member?.roles) { roles = Set(member?.roles ?? []) }
        .task { ownerKeys = canEdit && org.isOwner ? await org.ownerKeysAvailable() : false }
        .sheet(item: $confirmation) { OrgConfirmSheet(confirmation: $0) }
    }

    @ViewBuilder private func content(_ member: FfiOrgMember) -> some View {
        if org.serverAccessPending.contains(member.accountId) {
            Section {
                Label("org.access.notUpdated", systemImage: "exclamationmark.icloud")
                    .foregroundStyle(.orange)
                Button("org.access.retry", action: retryAccess)
                    .disabled(retrying)
                    .accessibilityIdentifier("org.member.retryAccess")
            } footer: {
                Text("org.access.notUpdated.footer")
            }
        }
        Section {
            LabeledContent("org.summary.state") {
                Text(OrgText.state(member.state)).foregroundStyle(OrgText.stateColor(member.state))
            }
        }
        Section {
            ForEach(member.devices, id: \.fingerprint) { OrgDeviceRow(device: $0) }
        } header: {
            Text("org.summary.devices")
        }
        Section {
            Toggle(OrgText.role(.owner), isOn: .constant(isHeadOwner || member.roles.contains(.owner)))
                .disabled(true)
            ForEach(Self.toggled, id: \.self) { role in
                Toggle(OrgText.role(role), isOn: binding(role))
                    .disabled(!canEdit || member.state.isRemoved)
                    .accessibilityIdentifier("org.member.role.\(role)")
            }
            if canEdit, roles != Set(member.roles) {
                Button("org.confirm.saveRoles") {
                    prepare(.setRoles(accountId: member.accountId, roles: OrgText.roleOrder.filter(roles.contains)))
                }
                .disabled(preparing)
                .accessibilityIdentifier("org.member.saveRoles")
            }
        } header: {
            Text("org.summary.roles")
        } footer: {
            if !OrgConsole.isConsoleDevice { Text("org.console.elsewhere") }
        }
        if canEdit {
            actions(member)
        }
        if let errorMessage {
            Section {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
            }
        }
    }

    @ViewBuilder private func actions(_ member: FfiOrgMember) -> some View {
        Section {
            // R19: an owner removed from the head keeps the Admin bit until someone takes it.
            if member.formerOwner, member.roles.contains(.admin), !isHeadOwner, !member.state.isRemoved {
                Button("org.action.removeAdmin") {
                    prepare(.setRoles(accountId: member.accountId, roles: member.roles.filter { $0 != .admin }))
                }
                .accessibilityIdentifier("org.member.removeAdmin")
            }
            // R10: the owners change only while the head has exactly one owner (quorum 1).
            if org.isOwner, ownerKeys, member.state == .active, !isHeadOwner, org.state?.owners.count == 1 {
                Button("org.action.makeOwner") { confirmMakeOwner(member) }
                    .accessibilityIdentifier("org.member.makeOwner")
            }
            switch member.state {
            case .active:
                Button("org.action.suspend", role: .destructive) { prepare(.suspend(accountId: member.accountId)) }
                    .accessibilityIdentifier("org.member.suspend")
            case .suspended:
                Button("org.action.reactivate") { prepare(.reactivate(accountId: member.accountId)) }
                    .accessibilityIdentifier("org.member.reactivate")
            case .invited, .removed:
                EmptyView()
            }
            if !member.state.isRemoved {
                Button("org.action.remove", role: .destructive) { prepare(.remove(accountId: member.accountId)) }
                    .accessibilityIdentifier("org.member.remove")
            }
        }
        .disabled(preparing)
    }

    private func binding(_ role: FfiOrgRole) -> Binding<Bool> {
        Binding(
            get: { roles.contains(role) },
            set: { on in
                if on { roles.insert(role) } else { roles.remove(role) }
            })
    }

    /// The local summary first; the sheet shows it and signs on Confirm.
    private func prepare(_ edit: FfiRosterEdit) {
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

    /// The owners of the head plus this member (one owner today: quorum 1, R10).
    private func confirmMakeOwner(_ member: FfiOrgMember) {
        let owners = (org.state?.owners ?? []) + [member.accountId]
        let name = OrgText.name(of: member, isMe: false)
        confirmation = OrgConfirmation(
            title: String(localized: "org.confirm.makeOwner \(name)"),
            rows: [
                .init(
                    label: String(localized: "org.summary.roles"),
                    value: "\(OrgText.roles(member.roles)) → \(OrgText.roles(member.roles + [.owner]))")
            ],
            perform: { password in try await org.setOwners(owners, password: password) })
    }
}

extension FfiMemberState {
    /// Removed for good, whatever its date and author.
    var isRemoved: Bool {
        if case .removed = self { return true }
        return false
    }
}
