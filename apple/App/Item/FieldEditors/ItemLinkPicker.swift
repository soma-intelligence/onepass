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
                    Text("Choisir un élément")
                }
            }
            .accessibilityIdentifier("editor.field.\(field.id)")
            Spacer()
            if linkedID != nil {
                Button("Retirer", systemImage: "xmark.circle.fill") { value = .empty }
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
    var title: LocalizedStringKey = "Lier un élément"
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
                        ItemIcon(type: summary.itemType, title: summary.title, siteIcon: nil, size: 30)
                        VStack(alignment: .leading) {
                            Text(summary.title).foregroundStyle(.primary)
                            if !summary.subtitle.isEmpty {
                                Text(summary.subtitle).font(.footnote).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .searchable(text: $query, prompt: Text("Rechercher"))
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
/// "entra_id", "oidc:<domain>". Shown as a monochrome letter mark, never the brand's logo.
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

/// The monochrome mark of a provider: its letters on a neutral rounded square.
struct ProviderMark: View {
    let provider: LoginProvider?
    var size: CGFloat = 20

    var body: some View {
        RoundedRectangle(cornerRadius: size / 4, style: .continuous)
            .fill(.primary.opacity(0.1))
            .frame(width: size, height: size)
            .overlay {
                if let provider {
                    Text(provider.mark)
                        .font(.system(size: size * (provider.mark.count > 1 ? 0.42 : 0.55), weight: .bold, design: .rounded))
                } else {
                    Image(systemName: "key.fill").font(.system(size: size * 0.48, weight: .semibold))
                }
            }
            .accessibilityHidden(true)
    }
}

/// Editor card of a login: "Se connecte avec" a provider (chips) or "Aucun (mot de passe)". A chosen
/// provider asks which account item it uses: the logins that look like that provider's account,
/// or any other item.
struct LoginMethodCard: View {
    @Environment(AppModel.self) private var model
    @Binding var item: FfiItem
    @State private var choosing: LoginProvider?

    private var current: (provider: String, accountItemID: String)? { item.signInProvider }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            EditorLabel("se connecte avec").padding(.leading, 16)
            EditorCard {
                ChipFlow(spacing: 8) {
                    chip(nil)
                    ForEach(LoginProvider.primary) { provider in chip(provider) }
                    otherProviders
                }
                .editorRowPadding()
                if let current {
                    CardDivider()
                    HStack(spacing: 10) {
                        Text("Compte utilisé")
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button {
                            choosing = LoginProvider(rawValue: current.provider)
                        } label: {
                            Label(ItemLinkPicker.title(of: current.accountItemID, in: model.session), systemImage: "link")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityIdentifier("editor.signIn.account")
                    }
                    .editorRowPadding()
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

    private func isCurrent(_ provider: LoginProvider?) -> Bool {
        current?.provider == provider?.rawValue
    }

    private func chip(_ provider: LoginProvider?) -> some View {
        let selected = isCurrent(provider)
        return Button {
            if let provider { choosing = provider } else { item.setSignInProvider(nil, accountItemID: nil) }
        } label: {
            HStack(spacing: 7) {
                ProviderMark(provider: provider, size: 20)
                Text(provider?.name ?? String(localized: "Aucun (mot de passe)"))
                    .font(.callout.weight(.medium))
                    .lineLimit(1)
            }
            .padding(.leading, 5)
            .padding(.trailing, 11)
            .padding(.vertical, 5)
            .background(selected ? AnyShapeStyle(Theme.accent.opacity(0.22)) : AnyShapeStyle(.fill.tertiary), in: Capsule())
            .overlay {
                Capsule().strokeBorder(selected ? AnyShapeStyle(Theme.accent) : AnyShapeStyle(.white.opacity(0.08)))
            }
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier("editor.signIn.\(provider?.rawValue ?? "none")")
    }

    /// The other providers, behind one chip (or the chosen one when it is among them).
    private var otherProviders: some View {
        let others = LoginProvider.allCases.filter { !LoginProvider.primary.contains($0) }
        let chosen = others.first { isCurrent($0) }
        return Menu {
            ForEach(others) { provider in
                Button(provider.name) { choosing = provider }
            }
        } label: {
            HStack(spacing: 7) {
                if let chosen { ProviderMark(provider: chosen, size: 20) }
                Text(chosen?.name ?? String(localized: "Autre…")).font(.callout.weight(.medium))
                Image(systemName: "chevron.down").font(.system(size: 9, weight: .bold))
            }
            .padding(.leading, chosen == nil ? 11 : 5)
            .padding(.trailing, 11)
            .padding(.vertical, 5)
            .background(chosen != nil ? AnyShapeStyle(Theme.accent.opacity(0.22)) : AnyShapeStyle(.fill.tertiary), in: Capsule())
            .overlay {
                Capsule().strokeBorder(chosen != nil ? AnyShapeStyle(Theme.accent) : AnyShapeStyle(.white.opacity(0.08)))
            }
            .contentShape(Capsule())
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .fixedSize()
        .accessibilityIdentifier("editor.signIn.other")
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
                        Text("Aucun élément ne ressemble à un compte \(provider.name).")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(accounts, id: \.id) { summary in
                        Button {
                            onPick(summary.id)
                        } label: {
                            HStack(spacing: 12) {
                                ItemIcon(type: summary.itemType, title: summary.title, siteIcon: nil, size: 30)
                                VStack(alignment: .leading) {
                                    Text(summary.title).foregroundStyle(.primary)
                                    if !summary.subtitle.isEmpty {
                                        Text(summary.subtitle).font(.footnote).foregroundStyle(.secondary)
                                    }
                                }
                            }
                            .contentShape(.rect)
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("signIn.account.\(summary.title)")
                    }
                } header: {
                    Text("Comptes \(provider.name)")
                }
                Section {
                    Button("Choisir un autre élément…", systemImage: "magnifyingglass") { pickingOther = true }
                        .accessibilityIdentifier("signIn.other")
                }
            }
            .navigationTitle(Text("Quel compte \(provider.name) utilises-tu ?"))
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
