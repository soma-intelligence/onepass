import SwiftUI
import VaultKit

/// What the sharing screens need from the app beyond the session (sharing plan 4, Task 9).
extension AppModel {
    /// This device's keys for contact cards and recovery cancels. None until the Swift plan of key
    /// rotation v2 lands (device keys in the Keychain and the Secure Enclave): the verification and
    /// recovery screens say so instead of starting.
    var deviceKeys: (any DeviceKeySource)? { nil }

    /// What the contact flows need: the device keys, the zone transport that makes a pair's
    /// mailbox, the invitation drops and the Soma instance. None until the device keys exist and
    /// the zone transport is wired here (the same plan).
    var contactServices: ContactServices? { nil }

    /// The account syncs through a mailbox (the Emergency Kit matters for recovery, spec 11.7).
    var syncsThroughMailbox: Bool { mailbox != nil }

    /// "Vus par un ancien membre" (sharing spec 10.4): the ids still live in the list.
    var seenByFormerMemberIDs: Set<String> {
        let seen = session.sharing.seenByFormerMembers
        guard !seen.isEmpty else { return [] }
        return Set(session.summaries.filter { seen.contains($0.id) && $0.trashedAt == nil }.map(\.id))
    }

    /// Reads the sharing state again; a failure leaves the shown state as it was.
    func refreshSharing() async {
        try? await session.refreshSharing()
    }
}

/// The contact flows' dependencies (see `AppModel.contactServices`).
struct ContactServices {
    let keys: any DeviceKeySource
    let creator: any ContactZoneCreating
    let drops: any InviteDrops
    let hosted: URL
}

extension FfiRole {
    /// The role's name in the screens (spec 10.2).
    var title: LocalizedStringKey {
        switch self {
        case .read: "sharing.role.read"
        case .write: "sharing.role.write"
        case .manage: "sharing.role.manage"
        }
    }
}

/// "Non vérifié" next to a contact added by link (spec 5.3.2, question 1).
struct UnverifiedBadge: View {
    var body: some View {
        Text("sharing.contact.unverified")
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .foregroundStyle(.orange)
            .background(.orange.opacity(0.14), in: Capsule())
            .accessibilityIdentifier("sharing.contact.unverified")
    }
}

/// A short error line under a form.
struct SharingErrorSection: View {
    let message: String?

    var body: some View {
        if let message {
            Section {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("sharing.error")
            }
        }
    }
}

/// The screens that need this device's keys, before they exist (FINDING of plan 4).
struct DeviceKeysUnavailableView: View {
    var body: some View {
        ContentUnavailableView(
            "sharing.keys.unavailable.title", systemImage: "key.slash",
            description: Text("sharing.keys.unavailable.message"))
            .accessibilityIdentifier("sharing.keys.unavailable")
    }
}
