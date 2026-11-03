import SwiftUI
import VaultKit

/// Réglages > Famille (spec 11.2): members and roles, the reminder to add a second organizer while
/// there is one (decision 13), the invitations, recovery enrollment and the members who chose this
/// account as their organizer.
struct FamilyView: View {
    @Environment(AppModel.self) private var model
    @State private var inviting = false
    @State private var enrolling = false
    @State private var errorMessage: String?

    private var sharing: SharingSnapshot { model.session.sharing }

    var body: some View {
        Form {
            if let family = sharing.family {
                if family.needsSecondOrganizer {
                    Section {
                        Label("family.secondOrganizer", systemImage: "person.2.badge.gearshape")
                            .foregroundStyle(.orange)
                            .accessibilityIdentifier("family.secondOrganizer")
                    }
                }
                Section {
                    ForEach(family.members, id: \.accountId) { member in
                        HStack {
                            Text(member.nameLocal.isEmpty ? String(localized: "sharing.member.you") : member.nameLocal)
                            Spacer(minLength: 0)
                            Text(member.role == .organizer ? "family.organizer" : "family.member")
                                .foregroundStyle(.secondary)
                        }
                    }
                    if family.iAmOrganizer {
                        Button {
                            inviting = true
                        } label: {
                            Label("family.invite", systemImage: "person.badge.plus")
                        }
                        .accessibilityIdentifier("family.invite")
                    }
                } header: {
                    Text("family.members")
                }
                recoverySection(family)
                if !sharing.helpers.isEmpty {
                    Section {
                        ForEach(sharing.helpers, id: \.enrollmentId) { helper in
                            NavigationLink {
                                RecoveryHelperView(helper: helper)
                            } label: {
                                Text(VaultSession.helperMessage(helper))
                            }
                        }
                    }
                }
            } else {
                Section {
                    Text("family.empty").foregroundStyle(.secondary)
                    Button("family.create") {
                        act { _ = try await model.session.createFamily(vaultName: String(localized: "family.vaultName")) }
                    }
                    .accessibilityIdentifier("family.create")
                }
            }
            if !sharing.familyInvites.isEmpty {
                Section {
                    ForEach(sharing.familyInvites, id: \.id) { invite in
                        Button("family.join \(invite.fromNameLocal)") {
                            act { _ = try await model.session.acceptFamilyInvite(invite.id) }
                        }
                    }
                }
            }
            SharingErrorSection(message: errorMessage)
        }
        .settingsPage("settings.family.title")
        .task { await model.refreshSharing() }
        .sheet(isPresented: $inviting) { FamilyInviteSheet() }
        .sheet(isPresented: $enrolling) { RecoveryEnrollView() }
    }

    @ViewBuilder private func recoverySection(_ family: FfiFamily) -> some View {
        Section {
            if let enrollment = sharing.recoveryEnrollment {
                LabeledContent("recovery.enrolledWith", value: enrollment.organizerNameLocal)
            } else if !family.iAmOrganizer {
                Button("recovery.enroll.title") { enrolling = true }
                    .accessibilityIdentifier("recovery.enroll")
            }
        } header: {
            Text("recovery.section")
        }
    }

    private func act(_ work: @escaping () async throws -> Void) {
        errorMessage = nil
        Task {
            do { try await work() } catch { errorMessage = VaultError(error).localizedMessage }
        }
    }
}

/// Invite a contact into the family, as a member or an organizer.
private struct FamilyInviteSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                ForEach(model.session.sharing.contacts.filter { $0.level == .verified }, id: \.accountId) { contact in
                    Menu {
                        Button("family.member") { invite(contact, .member) }
                        Button("family.organizer") { invite(contact, .organizer) }
                    } label: {
                        ContactRow(contact: contact)
                    }
                }
                SharingErrorSection(message: errorMessage)
            }
            .formStyle(.grouped)
            .navigationTitle(Text("family.invite"))
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Annuler") { dismiss() } }
            }
        }
    }

    private func invite(_ contact: FfiContact, _ role: FfiFamilyRole) {
        Task {
            do {
                _ = try await model.session.inviteToFamily(contact.accountId, role: role)
                dismiss()
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
        }
    }
}
