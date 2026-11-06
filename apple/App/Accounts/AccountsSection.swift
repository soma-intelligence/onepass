import DesignKit
import SwiftUI
import VaultKit

/// An account's avatar: its initials (or the profile photo of the account shown) on the account's
/// color, and a small badge for a business or organisation account (multi-account spec 7).
struct AccountBadgeAvatar: View {
    let initials: String
    var photo: Image?
    let color: Color
    var badge: String?
    var size: CGFloat = 32

    var body: some View {
        AccountAvatar(initials: initials, photo: photo, size: size, tint: color)
            .overlay(alignment: .bottomTrailing) {
                if let badge {
                    Image(systemName: badge)
                        .font(.system(size: size * 0.26, weight: .semibold))
                        .foregroundStyle(.white)
                        .frame(width: size * 0.46, height: size * 0.46)
                        .background(Circle().fill(color))
                        .overlay { Circle().strokeBorder(Color(white: 1, opacity: 0.9), lineWidth: max(1, size * 0.045)) }
                        .offset(x: size * 0.12, y: size * 0.12)
                        .accessibilityHidden(true)
                }
            }
    }
}

/// One account in a list: avatar, name, kind and whether it is locked; a check on the account shown.
struct AccountRowLabel: View {
    @Environment(AppModel.self) private var model
    let profile: AccountProfile
    var avatarSize: CGFloat = 36

    var body: some View {
        let active = profile.slot == model.accounts.activeSlot
        let locked = model.accounts.madeSession(profile.slot)?.state != .unlocked
        HStack(spacing: 12) {
            AccountBadgeAvatar(
                initials: model.initials(of: profile),
                photo: active ? model.profileImage : nil,
                color: AccountStyle.color(profile.color), badge: AccountStyle.badge(profile), size: avatarSize)
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: model.displayName(of: profile))
                    .font(.body.weight(active ? .semibold : .regular))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Text(verbatim: AccountStyle.kindName(profile.kind))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            if locked {
                Image(systemName: "lock.fill")
                    .font(.footnote)
                    .foregroundStyle(.tertiary)
                    .accessibilityLabel(Text("accounts.row.locked"))
            }
            if active {
                Image(systemName: "checkmark")
                    .font(.body.weight(.semibold))
                    .foregroundStyle(AccountStyle.color(profile.color))
                    .accessibilityHidden(true)
            }
        }
        .contentShape(.rect)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(active ? .isSelected : [])
    }
}

/// The accounts of the device at the top of the account panel (iPhone, iPad): each switches on tap,
/// then "Ajouter un compte", "Rechercher dans tous les comptes" when chosen, "Tout verrouiller" when
/// more than one is open. `perform` closes the panel first.
struct AccountsPanelSection: View {
    @Environment(AppModel.self) private var model
    /// The panel shows "Ajouter un compte" and "Tout verrouiller" among its own actions.
    var showsAdd = true
    var showsLockAll = true
    let perform: (AccountsPanelAction) -> Void

    var body: some View {
        VStack(spacing: 0) {
            Group(subviews: rows) { subviews in
                ForEach(Array(subviews.enumerated()), id: \.offset) { index, row in
                    if index > 0 { Divider().padding(.leading, 58) }
                    row
                }
            }
        }
    }

    @ViewBuilder private var rows: some View {
        ForEach(model.accounts.profiles) { profile in
            Button {
                perform(.switchTo(profile.slot))
            } label: {
                AccountRowLabel(profile: profile, avatarSize: 34)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("accounts.row.\(profile.isPrimary ? "primary" : profile.slot)")
        }
        if showsAdd {
            AccountsPanelLink(title: "accounts.add", symbol: "plus") { perform(.add) }
                .accessibilityIdentifier("accounts.add")
        }
        if model.accounts.unifiedSearch, model.accounts.hasSeveralAccounts {
            AccountsPanelLink(title: "accounts.searchAll", symbol: "magnifyingglass") { perform(.searchAll) }
                .accessibilityIdentifier("accounts.searchAll")
        }
        if showsLockAll, model.accounts.unlockedProfiles.count > 1 {
            AccountsPanelLink(title: "accounts.lockAll", symbol: "lock.fill") { perform(.lockAll) }
                .accessibilityIdentifier("accounts.lockAll")
        }
    }
}

/// What a row of the accounts section asks for.
enum AccountsPanelAction: Equatable {
    case switchTo(String), add, searchAll, lockAll
}

extension AppModel {
    /// Runs an accounts section action once the panel or menu is gone.
    func runAccountAction(_ action: AccountsPanelAction) {
        switch action {
        case .switchTo(let slot): perform(.switchAccount(slot))
        case .add: showAddAccount = true
        case .searchAll: showAllAccountsSearch = true
        case .lockAll: perform(.lockAll)
        }
    }
}

private struct AccountsPanelLink: View {
    let title: LocalizedStringKey
    let symbol: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: symbol)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .frame(width: 34, height: 34)
                    .background(Circle().fill(Color.primary.opacity(0.06)))
                Text(title)
                    .foregroundStyle(.primary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
    }
}

/// The same choices as menu items (the Mac account menu, menus that hold only buttons).
struct AccountsMenuItems: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Section {
            ForEach(model.accounts.profiles) { profile in
                Toggle(isOn: Binding(
                    get: { profile.slot == model.accounts.activeSlot },
                    set: { if $0 { model.runAccountAction(.switchTo(profile.slot)) } }
                )) {
                    Label {
                        Text(verbatim: model.displayName(of: profile))
                        Text(verbatim: AccountStyle.kindName(profile.kind))
                    } icon: {
                        Image(systemName: profile.symbol)
                    }
                }
                .accessibilityIdentifier("accounts.menu.\(profile.isPrimary ? "primary" : profile.slot)")
            }
            Button("accounts.add", systemImage: "plus") { model.runAccountAction(.add) }
                .accessibilityIdentifier("accounts.add")
            if model.accounts.unifiedSearch, model.accounts.hasSeveralAccounts {
                Button("accounts.searchAll", systemImage: "magnifyingglass") { model.runAccountAction(.searchAll) }
            }
            if model.accounts.unlockedProfiles.count > 1 {
                Button("accounts.lockAll", systemImage: "lock") { model.runAccountAction(.lockAll) }
                    .accessibilityIdentifier("accounts.lockAll")
            }
        } header: {
            Text("accounts.title")
        }
    }
}
