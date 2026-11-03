import SwiftUI
import VaultKit

/// One contact: name, level, the safety number and, at the Link level, "Comparer le numéro de
/// sécurité" (spec 5.3.2).
struct ContactDetailView: View {
    @Environment(AppModel.self) private var model
    let accountID: String

    private var contact: FfiContact? {
        model.session.sharing.contacts.first { $0.accountId == accountID }
    }

    var body: some View {
        Form {
            if let contact {
                Section {
                    HStack {
                        Text(contact.nameLocal).font(.title3.weight(.semibold))
                        Spacer(minLength: 0)
                        if contact.level == .link {
                            UnverifiedBadge()
                        } else {
                            Label("sharing.contact.verified", systemImage: "checkmark.seal.fill")
                                .foregroundStyle(.green)
                                .font(.callout)
                        }
                    }
                } footer: {
                    if contact.level == .link { Text("sharing.contact.linkFooter") }
                }
                if contact.level == .link {
                    Section {
                        NavigationLink {
                            SafetyNumberView(contact: contact)
                        } label: {
                            Text("sharing.contact.compareSafetyNumber")
                        }
                        .accessibilityIdentifier("sharing.contact.compare")
                    }
                }
            }
        }
        .settingsPage("settings.contacts.title")
    }
}
