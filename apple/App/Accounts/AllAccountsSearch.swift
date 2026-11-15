import DesignKit
import SwiftUI
import VaultKit

/// Rechercher dans tous les comptes (multi-account spec 7, ruling P5): only when the user turned the
/// unified view on, only over the accounts unlocked now, each result under its account. Opening one
/// shows that account. The search of each account's own lists never crosses accounts.
struct AllAccountsSearch: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""

    var body: some View {
        let results = model.accounts.unifiedResults(query: query)
        let groups = Dictionary(grouping: results, by: \.account.slot)
        let locked = model.accounts.profiles.filter { !model.accounts.unlockedProfiles.contains($0) }
        NavigationStack {
            List {
                ForEach(model.accounts.profiles.filter { groups[$0.slot] != nil }) { profile in
                    Section {
                        ForEach(groups[profile.slot] ?? []) { result in
                            Button {
                                dismiss()
                                model.perform(.revealInAccount(
                                    profile.slot, ItemRef(vaultID: result.summary.vaultId, itemID: result.summary.id)))
                            } label: {
                                resultRow(result.summary, active: result.account.slot == model.accounts.activeSlot)
                            }
                            .buttonStyle(.plain)
                            .accessibilityIdentifier("accounts.search.result.\(result.summary.id)")
                        }
                    } header: {
                        HStack(spacing: 8) {
                            AccountBadgeAvatar(
                                initials: model.initials(of: profile), color: AccountStyle.color(profile.color),
                                size: 18)
                            Text(verbatim: model.displayName(of: profile))
                        }
                    }
                }
                if !locked.isEmpty {
                    Section {
                        ForEach(locked) { profile in
                            Label {
                                Text(verbatim: model.displayName(of: profile))
                                    .foregroundStyle(.secondary)
                            } icon: {
                                Image(systemName: "lock.fill").foregroundStyle(.tertiary)
                            }
                        }
                    } footer: {
                        Text("accounts.search.locked.footer")
                    }
                }
            }
            .overlay {
                if !query.isEmpty, results.isEmpty {
                    ContentUnavailableView.search(text: query)
                }
            }
            .searchable(text: $query, prompt: Text("accounts.search.prompt"))
            .navigationTitle("accounts.searchAll")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("common.done") { dismiss() }
                        .accessibilityIdentifier("accounts.search.done")
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 460, minHeight: 520)
        #endif
    }

    /// `active`: the result belongs to the account shown. Another account's chosen icon is not
    /// read (its vault is not open here): the row shows the automatic icon.
    private func resultRow(_ summary: FfiItemSummary, active: Bool) -> some View {
        HStack(spacing: 12) {
            ItemIconSource(summary, chosen: active) { icon in
                ItemIcon(type: summary.itemType, title: summary.title, siteIcon: icon, size: 32,
                    useCategory: summary.usesCategoryIcon, tint: ItemTint.color(named: summary.color),
                    domain: ItemIconResolver.registrableDomain(summary.primaryUrl))
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: summary.title).foregroundStyle(.primary).lineLimit(1)
                if !summary.listSubtitle.isEmpty {
                    Text(verbatim: summary.listSubtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 0)
        }
        .contentShape(.rect)
    }
}
