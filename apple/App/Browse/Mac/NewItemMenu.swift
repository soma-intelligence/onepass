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
    /// The pointer over "Plus de catégories": its fan of tiles opens a little wider.
    @State private var hoveringMore = false
    @FocusState private var searchFocused: Bool
    /// iPhone: height of the floating header, where the scrolled tiles fade out.
    @State private var headerHeight: CGFloat = 160
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// iPhone: the sheet stays up after a pick, the editor takes its place (`PhoneNewItemSheet`).
    private let inPhoneSheet: Bool

    init(inPhoneSheet: Bool = false) {
        self.inPhoneSheet = inPhoneSheet
        // iPhone: the full-height sheet lists every category under the six tiles.
        _showAll = State(initialValue: inPhoneSheet)
    }

    /// Closes the type picker: the whole sheet, or on iPhone only the picker (the editor follows).
    private func close() {
        if inPhoneSheet { model.showNewItemPicker = false } else { dismiss() }
    }

    #if os(iOS)
    private static let sideInset: CGFloat = 16
    private static let searchInset: CGFloat = 16
    private static let searchFont = Font.body
    private static let moreFont = Font.headline
    private static let fanTile: CGFloat = 28
    private static let fanStep: CGFloat = 18
    #else
    private static let sideInset: CGFloat = 28
    private static let searchInset: CGFloat = 60
    private static let searchFont = Font.title3
    private static let moreFont = Font.title3.weight(.medium)
    private static let fanTile: CGFloat = 34
    private static let fanStep: CGFloat = 26
    #endif

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
            #if os(iOS)
            // iPhone: the title and the search field float over the tiles, which scroll up under them
            // and fade out there as under every other header of the app.
            // The fade goes on the tiles, under the bar: the title and the field stay sharp on top.
            scrollContent
                .headerFade(color: Color(uiColor: .systemBackground), header: headerHeight)
                .safeAreaBar(edge: .top, spacing: 0) {
                    header
                        .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { headerHeight = $0 }
                }
            #else
            header
            scrollContent
            #endif

            Divider().padding(.horizontal, Self.sideInset)
            Button {
                close()
                if inPhoneSheet {
                    // The import sheet comes once this one has gone.
                    Task {
                        try? await Task.sleep(for: .milliseconds(450))
                        model.showImport = true
                    }
                } else {
                    model.showImport = true
                }
            } label: {
                Label("browse.importFromAnotherPassword", systemImage: "square.and.arrow.down")
                    .font(.body.weight(.medium))
            }
            .buttonStyle(.borderless)
            .padding(.vertical, 16)
            .accessibilityIdentifier("newItem.import")
        }
        #if os(macOS)
        .frame(width: 600, height: 620)
        #endif
        // iPhone: the grid first, the keyboard only once the field is touched.
        .onAppear { if !inPhoneSheet { searchFocused = true } }
    }

    /// The close button, "Que veux-tu ajouter ?" and the search field.
    private var header: some View {
        VStack(spacing: 0) {
            HStack {
                Spacer()
                Button {
                    close()
                } label: {
                    Image(systemName: "xmark").font(.body.weight(.semibold)).foregroundStyle(.secondary)
                        .frame(width: 28, height: 28)
                        #if os(iOS)
                        // 44 pt target around the 28 pt glyph.
                        .contentShape(Rectangle().inset(by: -8))
                        #else
                        .contentShape(.rect)
                        #endif
                }
                .buttonStyle(.plain)
                .keyboardShortcut(.cancelAction)
                .accessibilityLabel(Text("Fermer"))
                .accessibilityIdentifier("newItem.close")
            }
            .padding([.top, .horizontal], 14)

            Text("browse.whatDoWantTo")
                .font(.title.weight(.bold))
                .padding(.bottom, 16)

            searchField
                .padding(.horizontal, Self.searchInset)
                .padding(.bottom, 22)
        }
    }

    /// The tiles, the categories, or what the search found.
    private var scrollContent: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if trimmed.isEmpty {
                    LazyVGrid(columns: Self.columns, spacing: 12) {
                        ForEach(Self.featured, id: \.self) { type in
                            BigTypeTile(type: type) { pick(type) }
                        }
                    }
                    moreCategories
                    if showAll {
                        allCategories
                            .transition(revealTransition)
                    }
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
            .padding(.horizontal, Self.sideInset)
            .padding(.bottom, 16)
        }
        #if !os(visionOS)
        .scrollDismissesKeyboard(.immediately)
        #endif
        // No scroll bar flashing and resizing while the categories unfold: the sheet scrolls
        // with the trackpad or wheel, the bar stays out of the animation.
        .scrollIndicators(.hidden)
        .scrollBounceBehavior(.basedOnSize)
    }

    private static let columns = Array(repeating: GridItem(.flexible(), spacing: 12), count: 3)

    private var searchField: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("browse.searchForSiteOr", text: $query)
                .textFieldStyle(.plain)
                .font(Self.searchFont)
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
            withAnimation(foldAnimation) { showAll.toggle() }
        } label: {
            HStack {
                Text(showAll ? "Moins de catégories" : "Plus de catégories")
                    .font(Self.moreFont)
                    .lineLimit(1)
                Spacer(minLength: 4)
                ZStack {
                    ForEach(Array(Self.fanTypes.enumerated()), id: \.offset) { i, type in
                        let fan = fanPose(i)
                        CategoryTile(category: ItemCategory.of(type), size: Self.fanTile)
                            .rotationEffect(.degrees(fan.angle))
                            .scaleEffect(fan.scale)
                            .offset(x: fan.x, y: fan.y)
                            .shadow(color: .black.opacity(showAll ? 0.12 : 0.28), radius: hoveringMore ? 5 : 3,
                                y: hoveringMore ? 3 : 2)
                            // A small stagger from left to right: the fan unfolds and folds like a hand of cards.
                            .animation(reduceMotion ? .easeOut(duration: 0.2)
                                : .spring(duration: 0.45, bounce: 0.28).delay(Double(i) * 0.025),
                                value: hoveringMore)
                            .animation(reduceMotion ? .easeOut(duration: 0.2)
                                : .spring(duration: 0.5, bounce: 0.18).delay(Double(i) * 0.03),
                                value: showAll)
                    }
                }
                .frame(width: Self.fanStep * 6.2, height: 44)
                Image(systemName: "chevron.down")
                    .font(.body.weight(.semibold))
                    .rotationEffect(.degrees(showAll ? 180 : 0))
                    .foregroundStyle(hoveringMore ? .primary : .secondary)
                    .animation(reduceMotion ? nil : .spring(duration: 0.4, bounce: 0.2), value: showAll)
            }
            .padding(.horizontal, 18)
            .padding(.vertical, 14)
            .frame(maxWidth: .infinity)
            .background(hoveringMore ? AnyShapeStyle(.fill.quaternary) : AnyShapeStyle(.fill.quinary),
                in: .rect(cornerRadius: 14))
            .overlay { RoundedRectangle(cornerRadius: 14).strokeBorder(.white.opacity(hoveringMore ? 0.16 : 0.1)) }
            .contentShape(.rect(cornerRadius: 14))
        }
        .tileButtonStyle()
        .onHover { hovering in hoveringMore = hovering }
        .animation(.easeOut(duration: 0.15), value: hoveringMore)
        .accessibilityIdentifier("newItem.more")
    }

    /// The house fold (as DesignKit's iPhone `Motion.fold`, which the Mac target does not get):
    /// a short critically damped spring, a plain ease with Reduce Motion.
    private var foldAnimation: Animation {
        reduceMotion ? .easeOut(duration: 0.2) : .spring(duration: 0.34, bounce: 0)
    }

    /// The categories unfolding: they fade in while settling a few points down from under the row.
    private var revealTransition: AnyTransition {
        reduceMotion ? .opacity : .asymmetric(insertion: .opacity.combined(with: .offset(y: -8)), removal: .opacity)
    }

    private static let fanTypes: [FfiItemType] = [.router, .medicalRecord, .sshKey, .passport, .vehicle, .bankAccount]

    /// Where fan tile `i` sits. At rest: a loose hand of cards. Under the pointer: wider, more tilted,
    /// lifted. Open: gathered into a tidy stack against the chevron, as if put away.
    private func fanPose(_ i: Int) -> (x: CGFloat, y: CGFloat, angle: Double, scale: CGFloat) {
        let rest = CGFloat(i) * Self.fanStep - Self.fanStep * 2.7
        let tilt = Double(i % 3 - 1)
        let lift: CGFloat = i.isMultiple(of: 2) ? 6 : -6
        if showAll {
            return (Self.fanStep * 2.2 + CGFloat(i) * 3, CGFloat(i) * -1, tilt * 3, 0.82)
        }
        if hoveringMore, !reduceMotion {
            return (rest * 1.12, lift * 1.35 - 2, tilt * 15, 1.06)
        }
        return (rest, lift, tilt * 9, 1)
    }

    private var allCategories: some View {
        VStack(alignment: .leading, spacing: 18) {
            ForEach(Array(groups.enumerated()), id: \.element.id) { index, group in
                VStack(alignment: .leading, spacing: 8) {
                    Text(group.title)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .padding(.leading, 4)
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 168), spacing: 8)], spacing: 8) {
                        ForEach(group.types, id: \.self) { type in
                            // A common type already has its big tile above: another identifier.
                            let duplicate = trimmed.isEmpty && Self.featured.contains(type)
                            NewItemTile(type: type, identifier: duplicate ? "newItem.all.\(NewItemMenu.key(type))" : nil) {
                                pick(type)
                            }
                        }
                    }
                }
                .modifier(StaggeredReveal(index: index, reduceMotion: reduceMotion))
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
        close()
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
                        Text("browse.signsInWith \(provider.name)").font(.callout.weight(.medium))
                    }
                    .padding(.leading, 5)
                    .padding(.trailing, 11)
                    .padding(.vertical, 5)
                    .background(.fill.tertiary, in: Capsule())
                    .overlay { Capsule().strokeBorder(.white.opacity(0.08)) }
                    .contentShape(Capsule())
                }
                .tileButtonStyle()
                .accessibilityIdentifier("newItem.website.\(provider.rawValue)")
            }
        }
        .padding(.leading, 4)
    }

    /// A login named after the site, its address filled in, and its sign-in provider when one was
    /// chosen: its account item right away when only one login looks like it, else the editor asks.
    private func pickWebsite(_ site: (title: String, url: String), provider: LoginProvider? = nil) {
        close()
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

    // iPhone: three narrow tiles a row, the name on up to two lines.
    #if os(iOS)
    private static let art: CGFloat = 40
    private static let spacing: CGFloat = 12
    private static let font = Font.subheadline.weight(.semibold)
    private static let lines = 2
    private static let padding: CGFloat = 12
    private static let height: CGFloat = 104
    #else
    private static let art: CGFloat = 44
    private static let spacing: CGFloat = 18
    private static let font = Font.title3.weight(.medium)
    private static let lines = 1
    private static let padding: CGFloat = 16
    private static let height: CGFloat = 118
    #endif

    var body: some View {
        let category = ItemCategory.of(type)
        Button(action: action) {
            VStack(alignment: .leading, spacing: Self.spacing) {
                HStack(alignment: .top) {
                    CategoryTile(category: category, size: Self.art)
                    Spacer()
                    Image(systemName: "plus")
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(Theme.accent)
                        .opacity(hovering ? 1 : 0)
                }
                Text(category.singular)
                    .font(Self.font)
                    .foregroundStyle(.primary)
                    .lineLimit(Self.lines)
                    .minimumScaleFactor(0.8)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(Self.padding)
            .frame(maxWidth: .infinity, minHeight: Self.height, alignment: .topLeading)
            .background(hovering ? AnyShapeStyle(Theme.accent.opacity(0.16)) : AnyShapeStyle(.fill.quinary),
                in: .rect(cornerRadius: 14))
            .overlay {
                RoundedRectangle(cornerRadius: 14)
                    .strokeBorder(hovering ? AnyShapeStyle(Theme.accent.opacity(0.6)) : AnyShapeStyle(.white.opacity(0.1)))
            }
            .contentShape(.rect(cornerRadius: 14))
        }
        .tileButtonStyle()
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
                    Text("browse.newLoginFor \(title)").font(.body.weight(.medium))
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
        .tileButtonStyle()
        .accessibilityIdentifier("newItem.website")
    }
}

/// One type in the ⌘N grid: the type's colored glyph and its name, highlighted on hover.
private struct NewItemTile: View {
    let type: FfiItemType
    var identifier: String?
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
        .tileButtonStyle()
        .onHover { hovering = $0 }
        .help(category.singular)
        .accessibilityIdentifier(identifier ?? "newItem.\(NewItemMenu.key(type))")
    }
}

/// A group of "Toutes les catégories" settling in after the ones above it: it fades in and drops
/// the last few points into place, 40 ms after the previous group (Reduce Motion: a plain fade).
private struct StaggeredReveal: ViewModifier {
    let index: Int
    let reduceMotion: Bool
    @State private var shown = false

    func body(content: Content) -> some View {
        content
            .opacity(shown ? 1 : 0)
            .offset(y: shown || reduceMotion ? 0 : 10)
            .onAppear {
                withAnimation(reduceMotion ? .easeOut(duration: 0.2)
                    : .spring(duration: 0.42, bounce: 0.12).delay(Double(min(index, 6)) * 0.04)) {
                    shown = true
                }
            }
    }
}

extension View {
    /// The tiles of "Que veux-tu ajouter ?": plain on the Mac (hover does the work), pressed in on
    /// iPhone the moment the finger lands.
    @ViewBuilder fileprivate func tileButtonStyle() -> some View {
        #if os(iOS)
        buttonStyle(PressableButtonStyle())
        #else
        buttonStyle(.plain)
        #endif
    }
}
