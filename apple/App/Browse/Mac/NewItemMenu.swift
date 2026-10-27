import DesignKit
import SwiftUI
import VaultKit

/// The 26 item types grouped as in the architecture spec 5.4 (Accès, Finance, Identité, Biens et
/// contrats, Autres). Menu content: works inside a `Menu` (toolbar "Nouvel élément") and inside a
/// `List` (the ⌘N sheet, the iPhone sheet).
struct NewItemMenu: View {
    private let onPick: (FfiItemType) -> Void

    init(onPick: @escaping (FfiItemType) -> Void) {
        self.onPick = onPick
    }

    struct TypeGroup: Identifiable, Sendable {
        let title: LocalizedStringResource
        let types: [FfiItemType]
        var id: String { String(localized: title) }
    }

    static let groups: [TypeGroup] = [
        TypeGroup(title: "Accès", types: [.login, .password, .email, .server, .database, .router, .apiCredential, .sshKey]),
        TypeGroup(title: "Finance", types: [.creditCard, .bankAccount, .cryptoWallet, .subscription]),
        TypeGroup(title: "Identité", types: [
            .identity, .idCard, .passport, .driverLicense, .socialSecurityNumber, .medicalRecord, .membership,
            .rewardProgram,
        ]),
        TypeGroup(title: "Biens et contrats", types: [.insurance, .vehicle, .accessCode]),
        TypeGroup(title: "Autres", types: [.secureNote, .document, .softwareLicense]),
    ]

    /// Stable name of a type for accessibility identifiers: `newItem.login`, `newItem.creditCard`.
    static func key(_ type: FfiItemType) -> String { String(describing: type) }

    var body: some View {
        ForEach(Self.groups) { group in
            Section {
                ForEach(group.types, id: \.self) { type in
                    let category = ItemCategory.of(type)
                    Button {
                        onPick(type)
                    } label: {
                        Label(category.singular, systemImage: category.symbol)
                    }
                    .accessibilityIdentifier("newItem.\(Self.key(type))")
                }
            } header: {
                Text(group.title)
            }
        }
    }
}

/// ⌘N and the "+" button: "Que veux-tu ajouter ?". The six common types as large tiles, every
/// category behind "Plus de catégories", a search over the types that also offers a login for a
/// typed website, and the way in to the import. Return picks the first result.
struct NewItemSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""
    @State private var showAll = false
    @FocusState private var searchFocused: Bool

    static let featured: [FfiItemType] = [.login, .secureNote, .creditCard, .identity, .apiCredential, .document]

    private var trimmed: String { query.trimmingCharacters(in: .whitespaces) }

    private var groups: [NewItemMenu.TypeGroup] {
        guard !trimmed.isEmpty else { return NewItemMenu.groups }
        return NewItemMenu.groups.compactMap { group in
            let types = group.types.filter {
                ItemCategory.of($0).singular.localizedStandardContains(trimmed)
                    || ItemCategory.of($0).plural.localizedStandardContains(trimmed)
            }
            return types.isEmpty ? nil : NewItemMenu.TypeGroup(title: group.title, types: types)
        }
    }

    /// "github", "github.com", "https://github.com/login": a website to make a login for.
    private var website: (title: String, url: String)? {
        let text = trimmed.lowercased()
        guard text.count >= 2, !text.contains(" ") else { return nil }
        let host = URL(string: text.contains("://") ? text : "https://\(text)")?.host() ?? text
        let name = host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
        let label = name.split(separator: ".").first.map { $0.prefix(1).uppercased() + $0.dropFirst() } ?? name
        return (label, host.contains(".") ? "https://\(host)" : "")
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Spacer()
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark").font(.body.weight(.semibold)).foregroundStyle(.secondary)
                        .frame(width: 28, height: 28)
                        .contentShape(.rect)
                }
                .buttonStyle(.plain)
                .keyboardShortcut(.cancelAction)
                .accessibilityLabel(Text("Fermer"))
                .accessibilityIdentifier("newItem.close")
            }
            .padding([.top, .horizontal], 14)

            Text("Que veux-tu ajouter ?")
                .font(.title.weight(.bold))
                .padding(.bottom, 16)

            searchField
                .padding(.horizontal, 60)
                .padding(.bottom, 22)

            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if trimmed.isEmpty {
                        LazyVGrid(columns: Self.columns, spacing: 12) {
                            ForEach(Self.featured, id: \.self) { type in
                                BigTypeTile(type: type) { pick(type) }
                            }
                        }
                        moreCategories
                        if showAll { allCategories }
                    } else {
                        if let website {
                            WebsiteTile(title: website.title, host: website.url) { pickWebsite(website) }
                            signInChips(website)
                        }
                        if groups.isEmpty, website == nil {
                            ContentUnavailableView.search(text: query).padding(.top, 20)
                        } else {
                            allCategories
                        }
                    }
                }
                .padding(.horizontal, 28)
                .padding(.bottom, 16)
            }

            Divider().padding(.horizontal, 28)
            Button {
                dismiss()
                model.showImport = true
            } label: {
                Label("Importer depuis un autre gestionnaire", systemImage: "square.and.arrow.down")
                    .font(.body.weight(.medium))
            }
            .buttonStyle(.borderless)
            .padding(.vertical, 16)
            .accessibilityIdentifier("newItem.import")
        }
        #if os(macOS)
        .frame(width: 600, height: 620)
        #endif
        .onAppear { searchFocused = true }
    }

    private static let columns = Array(repeating: GridItem(.flexible(), spacing: 12), count: 3)

    private var searchField: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("Rechercher un site ou une catégorie", text: $query)
                .textFieldStyle(.plain)
                .font(.title3)
                .focused($searchFocused)
                .onSubmit(submit)
                .accessibilityIdentifier("newItem.search")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .background(.fill.quaternary, in: .rect(cornerRadius: 12))
        .overlay {
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(searchFocused ? AnyShapeStyle(Theme.accent) : AnyShapeStyle(.white.opacity(0.08)),
                    lineWidth: searchFocused ? 2 : 1)
        }
    }

    /// The wide "Plus de catégories" row, with a few other types fanned out on its right.
    private var moreCategories: some View {
        Button {
            withAnimation(.snappy) { showAll.toggle() }
        } label: {
            HStack {
                Text(showAll ? "Moins de catégories" : "Plus de catégories")
                    .font(.title3.weight(.medium))
                Spacer()
                ZStack {
                    ForEach(Array([FfiItemType.router, .medicalRecord, .sshKey, .passport, .vehicle, .bankAccount].enumerated()), id: \.offset) { i, type in
                        CategoryTile(category: ItemCategory.of(type), size: 34)
                            .rotationEffect(.degrees(Double(i % 3 - 1) * 9))
                            .offset(x: CGFloat(i) * 26 - 70, y: i.isMultiple(of: 2) ? 6 : -6)
                            .shadow(color: .black.opacity(0.25), radius: 3, y: 2)
                    }
                }
                .frame(width: 160, height: 44)
                .opacity(showAll ? 0.5 : 1)
                Image(systemName: "chevron.down")
                    .rotationEffect(.degrees(showAll ? 180 : 0))
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 18)
            .padding(.vertical, 14)
            .frame(maxWidth: .infinity)
            .background(.fill.quinary, in: .rect(cornerRadius: 14))
            .overlay { RoundedRectangle(cornerRadius: 14).strokeBorder(.white.opacity(0.1)) }
            .contentShape(.rect(cornerRadius: 14))
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("newItem.more")
    }

    private var allCategories: some View {
        VStack(alignment: .leading, spacing: 18) {
            ForEach(groups) { group in
                VStack(alignment: .leading, spacing: 8) {
                    Text(group.title)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .padding(.leading, 4)
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 168), spacing: 8)], spacing: 8) {
                        ForEach(group.types, id: \.self) { type in
                            NewItemTile(type: type) { pick(type) }
                        }
                    }
                }
            }
        }
        .padding(.top, 8)
    }

    private func submit() {
        if trimmed.isEmpty { pick(.login) }
        else if let first = groups.first?.types.first { pick(first) }
        else if let website { pickWebsite(website) }
    }

    private func pick(_ type: FfiItemType) {
        dismiss()
        model.perform(.newItem(type))
    }

    /// "Se connecte avec Google / Apple / GitHub / Microsoft" under the website tile.
    private func signInChips(_ site: (title: String, url: String)) -> some View {
        ChipFlow(spacing: 8) {
            ForEach(LoginProvider.primary) { provider in
                Button {
                    pickWebsite(site, provider: provider)
                } label: {
                    HStack(spacing: 7) {
                        ProviderMark(provider: provider, size: 20)
                        Text("Se connecte avec \(provider.name)").font(.callout.weight(.medium))
                    }
                    .padding(.leading, 5)
                    .padding(.trailing, 11)
                    .padding(.vertical, 5)
                    .background(.fill.tertiary, in: Capsule())
                    .overlay { Capsule().strokeBorder(.white.opacity(0.08)) }
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("newItem.website.\(provider.rawValue)")
            }
        }
        .padding(.leading, 4)
    }

    /// A login named after the site, its address filled in, and its sign-in provider when one was
    /// chosen: its account item right away when only one login looks like it, else the editor asks.
    private func pickWebsite(_ site: (title: String, url: String), provider: LoginProvider? = nil) {
        dismiss()
        model.perform(.newItem(.login))
        guard var draft = model.newItemDraft else { return }
        draft.item.title = site.title
        if !site.url.isEmpty {
            draft.addURL()
            if let last = draft.item.urls.indices.last { draft.item.urls[last].url = site.url }
        }
        if let provider {
            let accounts = provider.accounts(in: model.session, excluding: draft.item.id)
            if accounts.count == 1 {
                draft.item.setSignInProvider(provider.rawValue, accountItemID: accounts[0].id)
            } else {
                PendingSignInProvider.value = (draft.item.id, provider)
            }
        }
        model.newItemDraft = draft
    }
}

/// A large tile of the common types: the type's glyph, its name, a "+" on hover.
private struct BigTypeTile: View {
    let type: FfiItemType
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        let category = ItemCategory.of(type)
        Button(action: action) {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .top) {
                    CategoryTile(category: category, size: 44)
                    Spacer()
                    Image(systemName: "plus")
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(Theme.accent)
                        .opacity(hovering ? 1 : 0)
                }
                Text(category.singular)
                    .font(.title3.weight(.medium))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
            .padding(16)
            .frame(maxWidth: .infinity, minHeight: 118, alignment: .topLeading)
            .background(hovering ? AnyShapeStyle(Theme.accent.opacity(0.16)) : AnyShapeStyle(.fill.quinary),
                in: .rect(cornerRadius: 14))
            .overlay {
                RoundedRectangle(cornerRadius: 14)
                    .strokeBorder(hovering ? AnyShapeStyle(Theme.accent.opacity(0.6)) : AnyShapeStyle(.white.opacity(0.1)))
            }
            .contentShape(.rect(cornerRadius: 14))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.12), value: hovering)
        .accessibilityIdentifier("newItem.\(NewItemMenu.key(type))")
    }
}

/// "Nouvelle connexion pour GitHub": the typed text read as a website.
private struct WebsiteTile: View {
    let title: String
    let host: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                CategoryTile(category: ItemCategory.of(.login), size: 34)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Nouvelle connexion pour \(title)").font(.body.weight(.medium))
                    if !host.isEmpty {
                        Text(host).font(.callout).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Image(systemName: "return").foregroundStyle(.tertiary)
            }
            .padding(14)
            .background(Theme.accent.opacity(0.14), in: .rect(cornerRadius: 12))
            .contentShape(.rect(cornerRadius: 12))
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("newItem.website")
    }
}

/// One type in the ⌘N grid: the type's colored glyph and its name, highlighted on hover.
private struct NewItemTile: View {
    let type: FfiItemType
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        let category = ItemCategory.of(type)
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: category.symbol)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 28, height: 28)
                    .background(category.color.gradient, in: .rect(cornerRadius: 7))
                Text(category.singular)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                    .foregroundStyle(.primary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 7)
            .contentShape(.rect(cornerRadius: 9))
            .background(hovering ? AnyShapeStyle(.quaternary) : AnyShapeStyle(.clear), in: .rect(cornerRadius: 9))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help(category.singular)
        .accessibilityIdentifier("newItem.\(NewItemMenu.key(type))")
    }
}
