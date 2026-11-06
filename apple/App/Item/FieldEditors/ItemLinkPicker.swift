import DesignKit
import SwiftUI
import VaultKit

/// Link to another item: shows the linked title, opens a searchable list of items to pick one.
struct ItemLinkPicker: View {
    @Environment(AppModel.self) private var model
    let field: FfiField
    /// The item being edited, left out of the list.
    let ownID: String
    @Binding var value: FfiFieldValue
    @State private var picking = false

    private var linkedID: String? {
        if case .itemLink(let id) = value, !id.isEmpty { id } else { nil }
    }

    var body: some View {
        HStack {
            Button {
                picking = true
            } label: {
                if let id = linkedID {
                    Label(Self.title(of: id, in: model.session), systemImage: "link")
                } else {
                    Text("item.chooseItem")
                }
            }
            .accessibilityIdentifier("editor.field.\(field.id)")
            Spacer()
            if linkedID != nil {
                Button("common.remove", systemImage: "xmark.circle.fill") { value = .empty }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
            }
        }
        .sheet(isPresented: $picking) {
            ItemPickerList(excluding: ownID) { picked in
                value = .itemLink(itemId: picked.id)
                picking = false
            }
        }
    }

    static func title(of id: String, in session: VaultSession) -> String {
        session.summaries.first { $0.id == id }?.title ?? String(localized: "Élément introuvable")
    }
}

/// Searchable list of live items (no archive, no trash, no hidden vault).
struct ItemPickerList: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let excluding: String
    var title: LocalizedStringKey = "item.linkItem"
    let onPick: (FfiItemSummary) -> Void
    @State private var query = ""

    var body: some View {
        NavigationStack {
            List(model.session.items(filter: .all, query: query, sort: .title).filter { $0.id != excluding }, id: \.id) {
                summary in
                Button {
                    onPick(summary)
                } label: {
                    HStack(spacing: 12) {
                        ItemIcon(type: summary.itemType, title: summary.title, siteIcon: model.iconLoader.cachedIcon(for: summary.primaryUrl, title: summary.title), size: 30)
                        VStack(alignment: .leading) {
                            Text(summary.title).foregroundStyle(.primary)
                            if !summary.listSubtitle.isEmpty {
                                Text(summary.listSubtitle).font(.footnote).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .searchable(text: $query, prompt: Text("common.search"))
            .navigationTitle(title)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 380, minHeight: 420)
        #endif
    }
}

// MARK: - Se connecte avec

/// A sign-in provider of a login (`FfiLoginMethod.provider`), as the core spells it: "google",
/// "entra_id", "oidc:<domain>". Shown with the provider's own mark in one color (`ProviderMark`).
enum LoginProvider: String, CaseIterable, Identifiable {
    case google, apple, microsoft, github, facebook, x, linkedin, discord, slack, okta
    case entraID = "entra_id"

    var id: String { rawValue }

    /// The four offered first (editor chips, add sheet).
    static let primary: [LoginProvider] = [.google, .apple, .github, .microsoft]

    var name: String {
        switch self {
        case .google: "Google"
        case .apple: "Apple"
        case .microsoft: "Microsoft"
        case .github: "GitHub"
        case .facebook: "Facebook"
        case .x: "X"
        case .linkedin: "LinkedIn"
        case .discord: "Discord"
        case .slack: "Slack"
        case .okta: "Okta"
        case .entraID: "Microsoft Entra ID"
        }
    }

    /// The brand mark in `Assets.xcassets/Providers` (Simple Icons, CC0; each mark stays its
    /// owner's trademark and only names the provider), nil when there is none to use.
    var assetName: String? {
        switch self {
        case .google, .apple, .github, .facebook, .x, .discord, .okta: "provider-\(rawValue)"
        default: nil
        }
    }

    var mark: String {
        switch self {
        case .github: "GH"
        case .linkedin: "in"
        case .entraID: "E"
        default: String(name.prefix(1))
        }
    }

    /// Words that point at this provider's own account in a login's title or address.
    var keywords: [String] {
        switch self {
        case .google: ["google", "gmail"]
        case .apple: ["apple", "icloud"]
        case .microsoft: ["microsoft", "outlook", "live.com", "office", "hotmail"]
        case .github: ["github"]
        case .facebook: ["facebook", "meta"]
        case .x: ["x.com", "twitter"]
        case .linkedin: ["linkedin"]
        case .discord: ["discord"]
        case .slack: ["slack"]
        case .okta: ["okta"]
        case .entraID: ["entra", "microsoftonline", "azure"]
        }
    }

    /// "Google", "GitHub", or the domain of a custom OIDC or SAML provider.
    static func displayName(_ raw: String) -> String {
        if let known = LoginProvider(rawValue: raw) { return known.name }
        if let colon = raw.firstIndex(of: ":") { return String(raw[raw.index(after: colon)...]) }
        return raw
    }

    /// The live logins that look like this provider's account (title or address), the item being
    /// edited left out.
    @MainActor func accounts(in session: VaultSession, excluding ownID: String) -> [FfiItemSummary] {
        session.items(filter: .all, query: "", sort: .title).filter { summary in
            guard summary.id != ownID, summary.itemType == .login || summary.itemType == .email else { return false }
            let text = (summary.title + " " + (summary.primaryUrl ?? "")).lowercased()
            return keywords.contains { text.contains($0) }
        }
    }
}

extension FfiItem {
    /// A credit card's network from its number ("visa"...), nil when unknown or not a card.
    var cardBrandName: String? {
        guard itemType == .creditCard,
            let number = sections.lazy.flatMap(\.fields).first(where: { $0.id == "number" })?.value.text,
            !number.isEmpty
        else { return nil }
        let brand = cardBrand(number: number)
        return brand == "unknown" ? nil : brand
    }

    /// The provider the login signs in with, and the item of that account (the first one).
    var signInProvider: (provider: String, accountItemID: String)? {
        for method in loginMethods {
            if case .provider(let provider, let account, _) = method { return (provider, account) }
        }
        return nil
    }

    /// Sets (or with nil removes) the sign-in provider; password and passkey methods stay.
    mutating func setSignInProvider(_ provider: String?, accountItemID: String?) {
        loginMethods.removeAll { if case .provider = $0 { true } else { false } }
        if let provider, let accountItemID {
            loginMethods.append(.provider(provider: provider, accountItemId: accountItemID, relayEmail: nil))
        }
    }
}

/// A provider chosen in the add sheet whose account item is still to pick: the new login's editor
/// opens the account chooser for it.
@MainActor
enum PendingSignInProvider {
    static var value: (itemID: String, provider: LoginProvider)?
}

/// The mark of a provider in one color on a neutral rounded square: its logo when the catalog has
/// one, the four squares for Microsoft, else its letters.
struct ProviderMark: View {
    let provider: LoginProvider?
    var size: CGFloat = 20

    var body: some View {
        RoundedRectangle(cornerRadius: size / 4, style: .continuous)
            .fill(.primary.opacity(0.1))
            .frame(width: size, height: size)
            .overlay { glyph }
            .accessibilityHidden(true)
    }

    @ViewBuilder private var glyph: some View {
        if let provider, let asset = provider.assetName {
            Image(asset)
                .renderingMode(.template)
                .resizable()
                .scaledToFit()
                .frame(width: size * 0.56, height: size * 0.56)
        } else if provider == .microsoft || provider == .entraID {
            let cell = size * 0.25
            Grid(horizontalSpacing: size * 0.05, verticalSpacing: size * 0.05) {
                GridRow { Rectangle().frame(width: cell, height: cell); Rectangle().frame(width: cell, height: cell) }
                GridRow { Rectangle().frame(width: cell, height: cell); Rectangle().frame(width: cell, height: cell) }
            }
        } else if let provider {
            Text(provider.mark)
                .font(.system(size: size * (provider.mark.count > 1 ? 0.42 : 0.55), weight: .bold, design: .rounded))
        } else {
            Image(systemName: "key.fill").font(.system(size: size * 0.48, weight: .semibold))
        }
    }
}

/// The username row of a login in the editor. With no sign-in provider: the username field and an
/// "Avec…" menu at its end (Google, Apple, GitHub, Microsoft, then the others). With one: the
/// provider and the account item it uses, "Changer" to pick another account and a cross back to a
/// typed username. Picking a provider asks which account item it uses (`SignInAccountChooser`).
struct LoginUsernameRow<Field: View>: View {
    @Environment(AppModel.self) private var model
    @Binding var item: FfiItem
    let label: String
    var message: String?
    @ViewBuilder var field: Field
    @State private var choosing: LoginProvider?

    var body: some View {
        Group {
            if let current = item.signInProvider {
                // The chosen account stands in for the username; a tap offers to change it or to go
                // back to a typed username.
                Menu {
                    Button("item.changeAccount", systemImage: "arrow.triangle.2.circlepath") {
                        choosing = LoginProvider(rawValue: current.provider)
                    }
                    .accessibilityIdentifier("editor.signIn.account")
                    Button("item.useUsernameInstead", systemImage: "person.text.rectangle", role: .destructive) {
                        item.setSignInProvider(nil, accountItemID: nil)
                    }
                    .accessibilityIdentifier("editor.signIn.none")
                } label: {
                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            EditorLabel(label)
                            SignInAccountLine(provider: current.provider, accountItemID: current.accountItemID)
                        }
                        Spacer(minLength: 8)
                        Image(systemName: "chevron.up.chevron.down")
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(.tertiary)
                    }
                    .contentShape(.rect)
                }
                .menuStyle(.button)
                .buttonStyle(.plain)
                .menuIndicator(.hidden)
                .accessibilityIdentifier("editor.signIn.current")
            } else {
                HStack(alignment: .center, spacing: 10) {
                    EditorRow(label: label, message: message) { field }
                    providerMenu
                }
            }
        }
        .sheet(item: $choosing) { provider in
            SignInAccountChooser(provider: provider, ownID: item.id) { accountID in
                item.setSignInProvider(provider.rawValue, accountItemID: accountID)
                choosing = nil
            }
        }
        .onAppear {
            // "Se connecte avec Google" in the add sheet: ask for the account right away.
            if let pending = PendingSignInProvider.value, pending.itemID == item.id {
                PendingSignInProvider.value = nil
                choosing = pending.provider
            }
        }
    }

    /// "Avec…": the providers a login can sign in through.
    private var providerMenu: some View {
        Menu {
            Section("item.signsInWith") {
                ForEach(LoginProvider.primary) { provider in
                    Button(provider.name) { choosing = provider }
                }
            }
            Menu("item.other") {
                ForEach(LoginProvider.allCases.filter { !LoginProvider.primary.contains($0) }) { provider in
                    Button(provider.name) { choosing = provider }
                }
            }
        } label: {
            Label("item.signInWith", systemImage: "person.crop.circle.badge.checkmark")
                .font(.footnote.weight(.medium))
                .foregroundStyle(Theme.accent)
                .contentShape(.rect)
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .fixedSize()
        .accessibilityIdentifier("editor.signIn.menu")
    }
}

/// A sign-in provider and its account: the provider's mark, "Google", and the account item's title
/// under it (or nothing when that item is gone).
struct SignInAccountLine: View {
    @Environment(AppModel.self) private var model
    let provider: String
    let accountItemID: String

    var body: some View {
        let account = model.session.summaries.first { $0.id == accountItemID && $0.trashedAt == nil }
        HStack(spacing: 10) {
            if let account {
                ItemIcon(type: account.itemType, title: account.title, siteIcon: model.iconLoader.cachedIcon(for: account.primaryUrl, title: account.title), size: 30)
            } else {
                ProviderMark(provider: LoginProvider(rawValue: provider), size: 30)
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: account?.title ?? LoginProvider.displayName(provider))
                    .foregroundStyle(.primary)
                if let account, !account.listSubtitle.isEmpty {
                    Text(account.listSubtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// "Quel compte Google utilises-tu ?": the logins that look like that account, then "Choisir un autre
/// élément…" for any item.
private struct SignInAccountChooser: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let provider: LoginProvider
    let ownID: String
    let onPick: (String) -> Void
    @State private var pickingOther = false

    var body: some View {
        let accounts = provider.accounts(in: model.session, excluding: ownID)
        NavigationStack {
            List {
                Section {
                    if accounts.isEmpty {
                        Text("item.noItemLooksLike \(provider.name)")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(accounts, id: \.id) { summary in
                        Button {
                            onPick(summary.id)
                        } label: {
                            HStack(spacing: 12) {
                                ItemIcon(type: summary.itemType, title: summary.title, siteIcon: model.iconLoader.cachedIcon(for: summary.primaryUrl, title: summary.title), size: 30)
                                VStack(alignment: .leading) {
                                    Text(summary.title).foregroundStyle(.primary)
                                    if !summary.listSubtitle.isEmpty {
                                        Text(summary.listSubtitle).font(.footnote).foregroundStyle(.secondary)
                                    }
                                }
                            }
                            .contentShape(.rect)
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("signIn.account.\(summary.title)")
                    }
                } header: {
                    Text("item.accounts \(provider.name)")
                }
                Section {
                    Button("item.chooseAnotherItem", systemImage: "magnifyingglass") { pickingOther = true }
                        .accessibilityIdentifier("signIn.other")
                }
            }
            .navigationTitle(Text("item.whichAccountDoUse \(provider.name)"))
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 400, minHeight: 360)
        #endif
        .sheet(isPresented: $pickingOther) {
            ItemPickerList(excluding: ownID, title: "Choisir le compte") { picked in
                pickingOther = false
                onPick(picked.id)
            }
        }
    }
}

/// Lays chips out left to right, wrapping to a new line when the row is full.
struct ChipFlow: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, line: CGFloat = 0, widest: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > 0, x + size.width > width {
                y += line + spacing
                x = 0
                line = 0
            }
            x += size.width + spacing
            widest = max(widest, x - spacing)
            line = max(line, size.height)
        }
        return CGSize(width: proposal.width ?? widest, height: y + line)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, line: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > bounds.minX, x + size.width > bounds.maxX {
                y += line + spacing
                x = bounds.minX
                line = 0
            }
            view.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            line = max(line, size.height)
        }
    }
}
