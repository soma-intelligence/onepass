import SwiftUI
import VaultKit

/// A member of the organisation in the Members list: the name (or "You"), the roles as short text,
/// the state and the number of devices.
struct OrgMemberRow: View {
    let member: FfiOrgMember
    let isMe: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline) {
                Text(OrgText.name(of: member, isMe: isMe))
                    .font(.body.weight(.medium))
                    .lineLimit(1)
                Spacer(minLength: 8)
                Text(OrgText.state(member.state))
                    .font(.footnote)
                    .foregroundStyle(OrgText.stateColor(member.state))
            }
            HStack(spacing: 6) {
                Text(OrgText.roles(member.roles))
                Text(verbatim: "·")
                Text("org.member.devices \(member.devices.count)")
            }
            .font(.footnote)
            .foregroundStyle(.secondary)
            .lineLimit(1)
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("org.member.\(member.accountId)")
    }
}

/// The words the organisation screens use for roles, states, names and device fingerprints.
enum OrgText {
    /// The order roles are listed in, from the widest.
    static let roleOrder: [FfiOrgRole] = [
        .owner, .admin, .userManager, .policyManager, .auditor, .recoveryOfficer, .provisioner,
    ]

    static func role(_ role: FfiOrgRole) -> String {
        switch role {
        case .owner: String(localized: "org.role.owner")
        case .admin: String(localized: "org.role.admin")
        case .userManager: String(localized: "org.role.userManager")
        case .policyManager: String(localized: "org.role.policyManager")
        case .auditor: String(localized: "org.role.auditor")
        case .recoveryOfficer: String(localized: "org.role.recoveryOfficer")
        case .provisioner: String(localized: "org.role.provisioner")
        }
    }

    /// "Owner, Admin", or "No role".
    static func roles(_ roles: [FfiOrgRole]) -> String {
        let sorted = roleOrder.filter(roles.contains)
        guard !sorted.isEmpty else { return String(localized: "org.role.none") }
        return sorted.map(role).joined(separator: ", ")
    }

    static func state(_ state: FfiMemberState) -> String {
        switch state {
        case .invited: String(localized: "org.state.invited")
        case .active: String(localized: "org.state.active")
        case .suspended: String(localized: "org.state.suspended")
        case .removed: String(localized: "org.state.removed")
        }
    }

    static func stateColor(_ state: FfiMemberState) -> Color {
        switch state {
        case .active: .secondary
        case .invited: .blue
        case .suspended: .orange
        case .removed: .red
        }
    }

    /// The member's name, "You" for this account, else the start of its account id.
    static func name(of member: FfiOrgMember, isMe: Bool) -> String {
        if isMe { return String(localized: "org.member.you") }
        if let name = member.displayName, !name.isEmpty { return name }
        return String(member.accountId.prefix(8))
    }

    /// The first 16 hex digits of a device fingerprint, in groups of 4.
    static func fingerprint(_ hex: String) -> String {
        let head = Array(hex.prefix(16))
        return stride(from: 0, to: head.count, by: 4)
            .map { String(head[$0..<min($0 + 4, head.count)]) }
            .joined(separator: " ")
    }
}

/// A device of a member or of a join request: its short fingerprint, and its name when known.
struct OrgDeviceRow: View {
    let device: FfiOrgDevice

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            if let name = device.name, !name.isEmpty {
                Text(name)
            }
            Text(OrgText.fingerprint(device.fingerprint))
                .font(.footnote.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
    }
}
