import SwiftUI
import VaultKit

/// Réglages > Contacts (sharing spec 5): the contact book, names from `name_local` only, "Non
/// vérifié" on a contact added by link, then the invitations, received items and key changes
/// waiting for an answer.
struct ContactsView: View {
    @Environment(AppModel.self) private var model
    @State private var verifying = false
    @State private var inviting = false

    private var sharing: SharingSnapshot { model.session.sharing }

    var body: some View {
        Form {
            Section {
                if sharing.contacts.isEmpty {
                    Text("sharing.contacts.empty").foregroundStyle(.secondary)
                }
                ForEach(sharing.contacts, id: \.accountId) { contact in
                    NavigationLink {
                        ContactDetailView(accountID: contact.accountId)
                    } label: {
                        ContactRow(contact: contact)
                    }
                    .accessibilityIdentifier("sharing.contact.\(contact.nameLocal)")
                }
            }
            Section {
                Button {
                    verifying = true
                } label: {
                    Label("sharing.verify.inPerson", systemImage: "qrcode.viewfinder")
                }
                .accessibilityIdentifier("sharing.contacts.addInPerson")
                Button {
                    inviting = true
                } label: {
                    Label("sharing.invite.byLink", systemImage: "link")
                }
                .accessibilityIdentifier("sharing.contacts.addByLink")
            } header: {
                Text("sharing.contacts.add")
            }
            waitingSection
        }
        .settingsPage("settings.contacts.title")
        .task { await model.refreshSharing() }
        .sheet(isPresented: $verifying) { VerifyContactView() }
        .sheet(isPresented: $inviting) { VerifyContactView(byLink: true) }
    }

    @ViewBuilder private var waitingSection: some View {
        if !sharing.shareInvites.isEmpty || !sharing.receivedItems.isEmpty || !sharing.identityChanges.isEmpty {
            Section {
                if !sharing.shareInvites.isEmpty {
                    NavigationLink {
                        ShareInvitesView()
                    } label: {
                        LabeledContent("sharing.invites.title", value: "\(sharing.shareInvites.count)")
                    }
                    .accessibilityIdentifier("sharing.invites")
                }
                if !sharing.receivedItems.isEmpty {
                    NavigationLink {
                        ReceivedItemsView()
                    } label: {
                        LabeledContent("sharing.received.title", value: "\(sharing.receivedItems.count)")
                    }
                    .accessibilityIdentifier("sharing.received")
                }
                if !sharing.identityChanges.isEmpty {
                    NavigationLink {
                        IdentityChangeView()
                    } label: {
                        LabeledContent("sharing.identity.title", value: "\(sharing.identityChanges.count)")
                    }
                    .accessibilityIdentifier("sharing.identityChanges")
                }
            }
        }
    }
}

/// One contact: the local name, and "Non vérifié" at the Link level.
struct ContactRow: View {
    let contact: FfiContact

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "person.crop.circle.fill")
                .font(.title2)
                .foregroundStyle(.secondary)
            Text(contact.nameLocal)
            Spacer(minLength: 0)
            if contact.level == .link { UnverifiedBadge() }
        }
    }
}
