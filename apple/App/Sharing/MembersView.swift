import SwiftUI
import VaultKit

/// The members of a shared vault (spec 10.2): names from the contact book, roles from the core.
/// Only a manager sees "Ajouter un membre", the role menus and "Retirer"; a reader sees the list.
struct MembersView: View {
    @Environment(AppModel.self) private var model
    let vaultID: String

    @State private var adding = false
    @State private var removing: FfiMember?
    @State private var errorMessage: String?
    @State private var notConfirmed: [String] = []

    private var vault: FfiSharedVault? {
        model.session.sharing.sharedVaults.first { $0.vaultId == vaultID }
    }

    private var manages: Bool { vault?.role == .manage }

    var body: some View {
        Form {
            if let vault {
                Section {
                    ForEach(vault.members, id: \.accountId) { member in
                        row(member)
                    }
                    if manages {
                        Button {
                            adding = true
                        } label: {
                            Label("sharing.vault.addMember", systemImage: "person.badge.plus")
                        }
                        .accessibilityIdentifier("sharing.members.add")
                    }
                } footer: {
                    if !notConfirmed.isEmpty { Text("sharing.member.notConfirmed \(notConfirmed.count)") }
                }
                refusals(vault)
                Section {
                    if vault.owner, vault.members.count == 1 {
                        Button("sharing.vault.stop") { act { _ = try await model.session.stopSharing(vaultID) } }
                    }
                    if !vault.owner {
                        Button("sharing.vault.leave", role: .destructive) {
                            act { try await model.session.leaveSharedVault(vaultID) }
                        }
                        .accessibilityIdentifier("sharing.vault.leave")
                    }
                }
                SharingErrorSection(message: errorMessage)
            }
        }
        .settingsPage("sharing.vault.members")
        .task {
            await model.refreshSharing()
            notConfirmed = (try? await model.session.membersNotConfirmed(in: vaultID)) ?? []
        }
        .sheet(isPresented: $adding) { ShareVaultSheet(vaultID: vaultID) }
        .sheet(item: $removing) { member in RemoveMemberSheet(vaultID: vaultID, member: member) }
    }

    @ViewBuilder private func row(_ member: FfiMember) -> some View {
        let me = vault?.members.first?.accountId == member.accountId && member.nameLocal.isEmpty
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(member.nameLocal.isEmpty ? String(localized: "sharing.member.you") : member.nameLocal)
                HStack(spacing: 6) {
                    Text(member.role.title)
                    if member.owner { Text("sharing.member.owner") }
                }
                .font(.footnote)
                .foregroundStyle(.secondary)
                if member.keysChanged { Text("sharing.member.keysChanged").font(.footnote).foregroundStyle(.orange) }
            }
            Spacer(minLength: 0)
            if member.level == .link, !member.nameLocal.isEmpty { UnverifiedBadge() }
            if manages, !member.owner, !me, !member.nameLocal.isEmpty {
                Menu {
                    ForEach([FfiRole.read, .write, .manage], id: \.self) { role in
                        Button {
                            act { _ = try await model.session.setRole(role, of: member.accountId, in: vaultID) }
                        } label: {
                            Text(role.title)
                        }
                        .disabled(role != .read && member.level == .link)
                    }
                    Divider()
                    Button("sharing.member.remove", role: .destructive) { removing = member }
                        .accessibilityIdentifier("sharing.member.remove")
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .accessibilityIdentifier("sharing.member.menu.\(member.nameLocal)")
            }
        }
        .accessibilityIdentifier("sharing.member.\(member.nameLocal)")
    }

    /// Spec 13.8 and the quota of the zone (review focus 4): the zone round's refusals.
    @ViewBuilder private func refusals(_ vault: FfiSharedVault) -> some View {
        if vault.identityPending {
            Section { Label("sharing.vault.identityPending", systemImage: "hourglass").foregroundStyle(.secondary) }
        }
    }

    private func act(_ work: @escaping () async throws -> Void) {
        errorMessage = nil
        Task {
            do { try await work() } catch { errorMessage = VaultError(error).localizedMessage }
        }
    }
}

extension FfiMember: @retroactive Identifiable {
    public var id: String { accountId }
}
