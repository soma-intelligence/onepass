#if os(iOS)
import DesignKit
import MapKit
import SwiftUI
import VaultKit

/// Accueil (spec 6.2, mockup `PhoneHome`): an inline title, the account name as a large secondary
/// heading, then cards: À proximité (asks for the position only once the card is opened, radius
/// and map in its header), the profile (the first identity), Favoris and Récents (items opened
/// during this session, memory only, emptied on lock), each foldable. The options button of the
/// navigation bar picks the cards shown. An empty vault shows "Créer ton premier élément".
struct HomeTab: View {
    @Environment(AppModel.self) private var model
    @Environment(\.phoneSearchActive) private var searchActive
    @Environment(\.openPhoneTab) private var openTab
    @Environment(\.horizontalSizeClass) private var sizeClass
    @AppStorage("onepass.home.favoritesOpen", store: AppModel.browseDefaults) private var favoritesOpen = true
    @AppStorage("onepass.home.recentsOpen", store: AppModel.browseDefaults) private var recentsOpen = true
    // The À proximité tile leads to the same list: its card is off unless chosen.
    @AppStorage("onepass.home.showsNearbyCard", store: AppModel.browseDefaults) private var showsNearby = false
    @AppStorage("onepass.home.showsProfile", store: AppModel.browseDefaults) private var showsProfile = true
    @AppStorage("onepass.home.showsFavorites", store: AppModel.browseDefaults) private var showsFavorites = true
    @AppStorage("onepass.home.showsRecents", store: AppModel.browseDefaults) private var showsRecents = true
    // Shown only when a crypto wallet carries watch data (spec 2026-11-02-crypto-watch).
    @AppStorage("onepass.home.showsCrypto", store: AppModel.browseDefaults) private var showsCrypto = true

    // Loaded here: a banner with nothing to show is an empty view, and an empty view never runs its task.
    @State private var duplicates = DuplicatesLoader()

    private var session: VaultSession { model.session }

    var body: some View {
        let counts = session.counts()
        let favorites = session.items(filter: .favorites, query: "", sort: .title)
        let recents = recentItems
        Group {
            if counts.all == 0 {
                firstItemState
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: Theme.Space.l) {
                        // Banners: these are list sections elsewhere, plain blocks here.
                        SyncRefusalSection()
                        AccountChangedSection()
                        // Under the search, above Tous les éléments and Favoris (spec 2026-11-03-duplicates).
                        if !searchActive { DuplicatesBanner(loader: duplicates) }
                        SharingBanners(horizontalPadding: 0)
                        tiles(all: counts.all, favorites: counts.favorites)
                        if model.travel.suggestion != .none, !searchActive {
                            TravelSuggestionCard()
                                .padding(Theme.Space.l)
                                .phoneCard()
                        }
                        if model.showsAutoFillTip, !searchActive {
                            AutoFillTipCard()
                                .padding(Theme.Space.l)
                                .phoneCard()
                        }
                        if model.showsSafariSetupCard, !searchActive {
                            SafariSetupCard()
                                .padding(Theme.Space.l)
                                .phoneCard()
                        }
                        if showsNearby { HomeNearbyCard() }
                        if showsCrypto { HomeCryptoCard() }
                        if showsProfile, let profile { HomeProfileCard(summary: profile) }
                        if showsFavorites {
                            HomeListCard(
                                title: "Favoris", symbol: "star.fill", color: .orange, isOpen: $favoritesOpen,
                                items: favorites, list: .favorites,
                                emptyText: "browse.tapItemsStarTo", id: "home.favorites")
                        }
                        if showsRecents {
                            HomeListCard(
                                title: "Récents", symbol: "clock.fill", color: Color(white: 0.55), isOpen: $recentsOpen,
                                items: recents, list: nil,
                                emptyText: "browse.itemsOpenAppearHere", id: "home.recents")
                        }
                    }
                    .padding(.horizontal, Theme.Space.gutter(regularWidth: sizeClass == .regular))
                    .padding(.bottom, Theme.Space.xl)
                }
                .background(PhoneBackground())
                .task(id: session.summariesRevision) { await duplicates.load(session) }
            }
        }
        // "Bonjour Camille", large, above the four tiles.
        .navigationTitle(greeting)
        .navigationBarTitleDisplayMode(.large)
        .toolbar {
            PhoneRootToolbar {
                Section("browse.showOnHome") {
                    Toggle("À proximité", systemImage: "location", isOn: $showsNearby)
                    Toggle("Profil", systemImage: "person.crop.circle", isOn: $showsProfile)
                    Toggle("Favoris", systemImage: "star", isOn: $showsFavorites)
                    Toggle("Récents", systemImage: "clock", isOn: $showsRecents)
                    Toggle("crypto.title", systemImage: "bitcoinsign", isOn: $showsCrypto)
                }
            }
        }
    }

    /// "Accueil", or "Bonjour" and the account's first name.
    private var greeting: String {
        let first = model.settings.displayName.split(separator: " ").first.map(String.init) ?? ""
        return first.isEmpty ? String(localized: "Accueil") : String(localized: "browse.hi \(first)")
    }

    private func tiles(all: Int, favorites: Int) -> some View {
        let score = model.watchtower.report.map { Int($0.score) }
        return Grid(horizontalSpacing: 12, verticalSpacing: 12) {
            GridRow {
                NavigationLink(value: PhoneRoute.list(.all)) {
                    HomeTile(title: "Tous les éléments", symbol: "square.grid.2x2.fill", color: Theme.accent) {
                        Text(all, format: .number)
                    }
                }
                .accessibilityIdentifier("home.all")
                NavigationLink(value: PhoneRoute.list(.favorites)) {
                    HomeTile(title: "Favoris", symbol: "star.fill", color: .orange) {
                        Text(favorites, format: .number)
                    }
                }
                .accessibilityIdentifier("home.favoritesTile")
            }
            GridRow {
                Button {
                    openTab(.watchtower)
                } label: {
                    HomeTile(title: "Watchtower", symbol: "checkmark.shield.fill", color: Sidebar.watchtowerColor) {
                        if let score {
                            Text(score, format: .number).foregroundStyle(ScoreGauge.color(score))
                        } else {
                            Image(systemName: "chevron.forward").font(.body.weight(.semibold)).foregroundStyle(.tertiary)
                        }
                    }
                }
                .accessibilityIdentifier("home.watchtower")
                NavigationLink(value: PhoneRoute.list(.nearby)) {
                    HomeTile(title: "À proximité", symbol: "location.fill", color: Color(red: 0x0A / 255, green: 0x84 / 255, blue: 0xFF / 255)) {
                        Text("browse.n2Km").font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
                    }
                }
                .accessibilityIdentifier("home.nearby")
            }
        }
        .buttonStyle(PressableButtonStyle())
    }


    /// The first identity, the account holder's card.
    private var profile: FfiItemSummary? {
        session.items(filter: .category(.identity), query: "", sort: .title).first
    }

    /// Recently opened items still present and active, newest first.
    private var recentItems: [FfiItemSummary] {
        let active = Dictionary(
            session.items(filter: .all, query: "", sort: .title).map { ($0.id, $0) },
            uniquingKeysWith: { first, _ in first })
        return session.recents.compactMap { active[$0] }
    }

    private var firstItemState: some View {
        VStack(spacing: Theme.Space.l) {
            Spacer()
            HStack(spacing: -10) {
                ForEach(Array([FfiItemType.login, .creditCard, .identity, .secureNote].enumerated()), id: \.offset) { i, type in
                    CategoryArtwork(type: type, size: 64)
                        .rotationEffect(.degrees(Double(i) * 8 - 12))
                        .shadow(color: .black.opacity(0.18), radius: 6, y: 3)
                }
            }
            .padding(.bottom, Theme.Space.s)
            Text("browse.vaultEmpty2")
                .font(.title2.weight(.bold))
            Text("browse.passwordsCardsIdentitiesNotes")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, Theme.Space.xxl)
            Button {
                model.showNewItemPicker = true
            } label: {
                Text("browse.createFirstItem")
                    .font(.headline)
                    .padding(.horizontal, Theme.Space.s)
                    .frame(height: 34)
            }
            .buttonStyle(.glassProminent)
            .accessibilityIdentifier("home.firstItem")
            Spacer()
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .background(PhoneBackground())
    }
}

/// The header line of a home card: the colored tile, the title and a subtitle, the card's own
/// controls, and the fold chevron. The title and the chevron fold the card.
private struct HomeCardHeader<Controls: View>: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let title: LocalizedStringKey
    var subtitle: String?
    let tile: AnyView
    @Binding var isOpen: Bool
    let id: String
    @ViewBuilder var controls: Controls

    var body: some View {
        HStack(spacing: Theme.Space.m) {
            Button(action: toggle) {
                HStack(spacing: Theme.Space.m) {
                    tile
                    VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                        Text(title).font(.headline).foregroundStyle(.primary)
                        if let subtitle {
                            Text(verbatim: subtitle)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .minimumScaleFactor(0.85)
                                .contentTransition(.numericText())
                        }
                    }
                    Spacer(minLength: 4)
                }
                .frame(minHeight: 44)
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityAddTraits(.isHeader)
            .accessibilityValue(isOpen ? Text("browse.expanded") : Text("browse.collapsed"))
            .accessibilityIdentifier(id)
            controls
            Button(action: toggle) {
                Image(systemName: "chevron.down")
                    .font(.footnote.weight(.bold))
                    .foregroundStyle(Theme.readableAccent)
                    .rotationEffect(.degrees(isOpen ? 0 : -90))
                    .frame(width: 32, height: 44)
                    .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityLabel(isOpen ? Text("browse.collapse") : Text("browse.expand"))
        }
        .padding(.horizontal, Theme.Space.l)
        .padding(.vertical, Theme.Space.xs)
    }

    private func toggle() {
        withAnimation(Motion.fold(reduceMotion: reduceMotion)) { isOpen.toggle() }
    }
}

/// Favoris or Récents: the header (tile, count, the ⋯ menu for Favoris, the chevron) then the rows.
private struct HomeListCard: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let title: LocalizedStringKey
    let symbol: String
    let color: Color
    @Binding var isOpen: Bool
    let items: [FfiItemSummary]
    /// The full list behind the ⋯ menu, when there is one.
    let list: ItemFilter?
    let emptyText: LocalizedStringKey
    let id: String

    var body: some View {
        VStack(spacing: 0) {
            HomeCardHeader(
                title: title, subtitle: items.isEmpty ? nil : ItemListColumn.countLabel(items.count),
                tile: AnyView(SymbolTile(symbol: symbol, color: color, size: 30)), isOpen: $isOpen, id: id
            ) {
                if let list, !items.isEmpty {
                    Menu {
                        NavigationLink(value: PhoneRoute.list(list)) {
                            Label("browse.showItems", systemImage: "list.bullet")
                        }
                    } label: {
                        Image(systemName: "ellipsis")
                            .font(.footnote.weight(.bold))
                            .foregroundStyle(.secondary)
                            .frame(width: 28, height: 28)
                            .background(Color.primary.opacity(0.08), in: Circle())
                            .frame(width: 44, height: 44)
                            .contentShape(.rect)
                    }
                    .accessibilityLabel(Text("app.actionsFor \(Text(title))"))
                }
            }
            if isOpen {
                Group {
                    if items.isEmpty {
                        Text(emptyText)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, Theme.Space.l)
                            .padding(.bottom, Theme.Space.l)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        Divider().padding(.leading, PhoneCard.headerTextInset)
                        PhoneItemRows(items: items, vaultName: { _ in nil })
                    }
                }
                .transition(Motion.reveal(reduceMotion: reduceMotion))
            }
        }
        .phoneCard()
    }
}

/// The profile: the first identity, one row (name and email) that opens it.
private struct HomeProfileCard: View {
    let summary: FfiItemSummary

    var body: some View {
        NavigationLink(value: PhoneRoute.item(ItemRef(vaultID: summary.vaultId, itemID: summary.id))) {
            HStack(spacing: Theme.Space.m) {
                Image(systemName: "person.fill")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 30, height: 30)
                    .background(Color.blue, in: Circle())
                VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                    Text("Profil").font(.headline).foregroundStyle(.primary)
                    Text(verbatim: [summary.title, summary.subtitle].filter { !$0.isEmpty }.joined(separator: ", "))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 4)
                Image(systemName: "chevron.forward")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, Theme.Space.l)
            .padding(.vertical, Theme.Space.m)
            .contentShape(.rect)
        }
        .itemZoomSource(ItemRef(vaultID: summary.vaultId, itemID: summary.id))
        .buttonStyle(RowHighlightButtonStyle())
        .phoneCard()
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("home.profile")
    }
}

/// À proximité: items saved with a place within the chosen radius, closest first, the distance in
/// a pill. The position is asked for only while the card is open (folded by default, so nothing
/// is asked at launch). The map shows where you are and the radius.
private struct HomeNearbyCard: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @AppStorage("onepass.home.nearbyOpen", store: AppModel.browseDefaults) private var isOpen = false
    @AppStorage("onepass.home.nearbyRadius", store: AppModel.browseDefaults) private var radius: Double = 2_000
    @AppStorage("onepass.home.nearbyMap", store: AppModel.browseDefaults) private var showsMap = false
    @State private var nearby = NearbyLoader()

    static let radii: [Double] = [500, 1_000, 2_000, 5_000, 10_000]

    var body: some View {
        VStack(spacing: 0) {
            HomeCardHeader(
                title: "À proximité", subtitle: subtitle,
                tile: AnyView(NearbyTile(size: 30)), isOpen: $isOpen, id: "home.nearby"
            ) {
                if isOpen {
                    Menu {
                        Picker("app.radius", selection: $radius) {
                            ForEach(Self.radii, id: \.self) { Text(verbatim: Self.label($0)).tag($0) }
                        }
                    } label: {
                        HStack(spacing: Theme.Space.xxs) {
                            Text(verbatim: Self.label(radius))
                            Image(systemName: "chevron.up.chevron.down").font(.caption2.weight(.semibold))
                        }
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .frame(minHeight: 44)
                        .contentShape(.rect)
                    }
                    .accessibilityLabel(Text("app.radius"))
                    .accessibilityValue(Text(verbatim: Self.label(radius)))
                    .accessibilityIdentifier("home.nearby.radius")
                    Button {
                        withAnimation(Motion.fold(reduceMotion: reduceMotion)) { showsMap.toggle() }
                    } label: {
                        Image(systemName: showsMap ? "map.fill" : "map")
                            .font(.body)
                            .foregroundStyle(Theme.readableAccent)
                            .contentTransition(.symbolEffect(.replace))
                            .frame(width: 36, height: 44)
                            .contentShape(.rect)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(showsMap ? Text("browse.hideMap") : Text("browse.showMap"))
                    .accessibilityIdentifier("home.nearby.map")
                }
            }
            if isOpen {
                VStack(spacing: 0) {
                    if showsMap, let origin = nearby.origin {
                        Map(initialPosition: .region(MKCoordinateRegion(
                            center: origin, latitudinalMeters: radius * 2.4, longitudinalMeters: radius * 2.4))) {
                            UserAnnotation()
                            MapCircle(center: origin, radius: radius)
                                .foregroundStyle(Theme.accent.opacity(0.12))
                                .stroke(Theme.accent.opacity(0.6), lineWidth: 1.5)
                        }
                        .id(radius)
                        .frame(height: 170)
                        .clipShape(.rect(cornerRadius: Theme.Radius.control, style: .continuous))
                        .padding(.horizontal, Theme.Space.l)
                        .padding(.bottom, Theme.Space.m)
                        .allowsHitTesting(false)
                        .transition(Motion.reveal(reduceMotion: reduceMotion))
                    }
                    content
                }
                .transition(Motion.reveal(reduceMotion: reduceMotion))
            }
        }
        .phoneCard()
        .task(id: NearbyKey(open: isOpen, radius: radius, revision: model.session.summariesRevision)) {
            guard isOpen else { return }
            await nearby.load(model.session, within: radius)
        }
        #if DEBUG
        // Captures: `-OnePassDemoNearby YES` opens the card.
        .onAppear { if UserDefaults.standard.bool(forKey: "OnePassDemoNearby") { isOpen = true } }
        #endif
    }

    private struct NearbyKey: Equatable {
        let open: Bool
        let radius: Double
        let revision: Int
    }

    private var subtitle: String? {
        guard isOpen, nearby.phase == .ready else { return nil }
        let count = nearby.items.count
        return count == 0
            ? String(localized: "browse.nothingWithin \(Self.label(radius))")
            : String(localized: "browse.within \(count) \(Self.label(radius))")
    }

    @ViewBuilder private var content: some View {
        switch nearby.phase {
        case .ready:
            if !nearby.items.isEmpty {
                Divider().padding(.leading, PhoneCard.headerTextInset)
                PhoneItemRows(
                    items: nearby.items.map(\.summary), vaultName: { _ in nil },
                    pill: { summary in
                        nearby.items.first { $0.summary.id == summary.id }.map { Self.pill($0.distance) }
                    })
            }
        case .idle, .locating:
            HStack(spacing: Theme.Space.s) {
                ProgressView().controlSize(.small)
                Text("browse.findingLocation").font(.subheadline).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Theme.Space.l)
            .padding(.bottom, Theme.Space.l)
        case .failed(.denied):
            VStack(alignment: .leading, spacing: Theme.Space.s) {
                Text("browse.allowOnepassToUse")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Button("app.openSettings") { LocationAccess.openSettings() }
                    .font(.subheadline.weight(.semibold))
                    .accessibilityIdentifier("home.nearby.openSettings")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Theme.Space.l)
            .padding(.bottom, Theme.Space.l)
        case .failed(.unavailable):
            HStack {
                Text("browse.cantTellWhereRight").font(.subheadline).foregroundStyle(.secondary)
                Spacer()
                Button("Réessayer") { Task { await nearby.load(model.session, within: radius) } }
                    .font(.subheadline.weight(.semibold))
            }
            .padding(.horizontal, Theme.Space.l)
            .padding(.bottom, Theme.Space.l)
        }
    }

    /// "500 m", "2 km": the radius, the same in French and English.
    static func label(_ meters: Double) -> String {
        meters < 1_000 ? "\(Int(meters)) m" : "\(Int(meters / 1_000)) km"
    }

    /// The distance pill of a row: "350 m", "1,2 km" (the list's label without its "à").
    static func pill(_ meters: Double) -> String {
        let label = LocationIndex.distanceLabel(meters)
        return label.hasPrefix("à ") ? String(label.dropFirst(2)) : label
    }
}

/// Item rows of a home card: the list rows of the Mac, a chevron, hairlines between rows. The card
/// around them belongs to the caller.
struct PhoneItemRows: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let items: [FfiItemSummary]
    let vaultName: (String) -> String?
    /// A short figure in a pill before the chevron (À proximité: the distance).
    var pill: (FfiItemSummary) -> String? = { _ in nil }

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(items.enumerated()), id: \.element.id) { index, summary in
                NavigationLink(value: PhoneRoute.item(ItemRef(vaultID: summary.vaultId, itemID: summary.id))) {
                    HStack(spacing: Theme.Space.s) {
                        ItemListRow(summary: summary, vaultName: vaultName(summary.vaultId))
                        if let pill = pill(summary) {
                            Text(verbatim: pill)
                                .font(.caption.weight(.medium))
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, Theme.Space.s)
                                .padding(.vertical, Theme.Space.xxs)
                                .background(Color.primary.opacity(0.08), in: Capsule())
                        }
                        Image(systemName: "chevron.forward")
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(.tertiary)
                            .accessibilityHidden(true)
                    }
                    .padding(.horizontal, Theme.Space.l)
                    .padding(.vertical, Theme.Space.s)
                    .contentShape(Rectangle())
                }
                .itemZoomSource(ItemRef(vaultID: summary.vaultId, itemID: summary.id))
                .buttonStyle(RowHighlightButtonStyle())
                // The hairline belongs to the row below it, so a row leaving takes its own line along.
                .overlay(alignment: .top) {
                    // Starts at the row title: padding, the 40 pt icon, spacing.
                    if index > 0 { Divider().padding(.leading, Theme.Space.l + 40 + Theme.Space.m) }
                }
                .transition(.opacity)
            }
        }
        // A favorite added or removed elsewhere: the rows around it slide to their new place.
        .animation(Motion.list(reduceMotion: reduceMotion), value: items.map(\.id))
    }
}

/// The surface of the iPhone cards: the grouped list's cell color, a hairline, rounded as the Mac
/// cards.
enum PhoneCard {
    static let radius: CGFloat = Theme.Radius.card
    /// Where a home card header's title starts (padding, the 30 pt tile, spacing): the hairline
    /// under the header starts there too.
    static let headerTextInset: CGFloat = Theme.Space.l + 30 + Theme.Space.m
}

extension View {
    func phoneCard() -> some View {
        modifier(PhoneCardSurface())
    }
}

/// The card's surface: the cell color, clipped to the card radius, a hairline.
private struct PhoneCardSurface: ViewModifier {
    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: PhoneCard.radius, style: .continuous)
        return content
            .background(Theme.card, in: shape)
            .clipShape(shape)
            .overlay { shape.strokeBorder(Theme.cardHairline) }
    }
}

/// The screen behind the iPhone cards: the grouped background, plain. The cards and the glass bars
/// carry the depth; a tinted wash on top read as decoration.
struct PhoneBackground: View {
    var body: some View {
        Theme.page
            .ignoresSafeArea()
    }
}

extension View {
    /// Grows the touch area of a small control (a fold header, a glyph) to 44 pt high without
    /// moving anything on screen.
    func tapTarget(height: CGFloat = 44) -> some View {
        frame(minHeight: height)
            .contentShape(.rect)
            .padding(.vertical, -max(0, height - 24) / 2)
    }
}

/// Small lowercase section label in the accent color (the Mac's field and card labels).
struct PhoneSectionLabel: View {
    let text: Text

    init(_ text: LocalizedStringKey) { self.text = Text(text) }
    init(verbatim text: String) { self.text = Text(verbatim: text) }

    var body: some View {
        text
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(PhoneSectionLabel.color)
    }

    /// The accent, lightened on dark backgrounds to keep 4.5:1.
    static let color = Theme.readableAccent
}

/// iPhone: a sync refusal (spec 8, "Données refusées") at the top of Accueil and Éléments. The data on
/// screen is local and stays readable, but the refused vault's changes no longer sync: the Mac has
/// its sidebar chip, the iPhone this banner.
struct SyncRefusalSection: View {
    @Environment(AppModel.self) private var model
    @State private var safeExitKind: String?

    var body: some View {
        if case .refused(let kind) = model.syncStatus {
            Section {
                VStack(alignment: .leading, spacing: Theme.Space.s) {
                    IntegrityBanner(kind: kind)
                    Text("browse.dataReceivedFromIcloud")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Button("app.seeSolutions") { safeExitKind = kind }
                        .font(.footnote.weight(.semibold))
                        .accessibilityIdentifier("sync.refused.safeExits")
                }
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets(top: 0, leading: 0, bottom: 0, trailing: 0))
                .accessibilityIdentifier("sync.refused.banner")
            }
            .sheet(item: Binding(get: { safeExitKind.map(RefusedKind.init) }, set: { safeExitKind = $0?.kind })) {
                SafeExitChooserSheet(kind: $0.kind)
            }
        }
    }
}
/// Accueil's way to the Crypto screen: the cached total (no request from here) and its change, or
/// "Désactivé" while the watch is off. Hidden until a crypto wallet carries an address or an xpub.
private struct HomeCryptoCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let watch = model.cryptoWatch
        let watched = watch.wallets.contains { !$0.addresses.isEmpty || $0.xpub != nil }
        Group {
            if watched {
                NavigationLink(value: PhoneRoute.crypto) {
                    HStack(spacing: Theme.Space.m) {
                        SymbolTile(symbol: "bitcoinsign", color: .orange, size: 34)
                        VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                            Text("crypto.title").font(.headline)
                            if let p = watch.isEnabled ? watch.portfolio() : nil, !p.holdings.isEmpty {
                                ChangeLabel(change: p.changePercent)
                            } else {
                                Text(watch.isEnabled ? "crypto.home.tapToRefresh" : "crypto.home.off")
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        Spacer(minLength: 8)
                        if watch.isEnabled, let p = watch.portfolio(), !p.holdings.isEmpty {
                            Text(verbatim: CryptoFormat.money(p.total, currency: p.currency))
                                .font(.title3.weight(.bold))
                                .monospacedDigit()
                                .lineLimit(1)
                                .minimumScaleFactor(0.7)
                        }
                        Image(systemName: "chevron.forward")
                            .font(.footnote.weight(.bold))
                            .foregroundStyle(.tertiary)
                    }
                    .padding(Theme.Space.l)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .phoneCard()
                    .contentShape(.rect(cornerRadius: PhoneCard.radius))
                }
                .buttonStyle(PressableButtonStyle())
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("home.crypto")
            }
        }
        .task { await model.prepareCryptoWatch() }
    }
}

/// One of the four tiles of Accueil: the Mac sidebar's colored tile, the figure on the right, the
/// name below.
private struct HomeTile<Value: View>: View {
    let title: LocalizedStringKey
    let symbol: String
    let color: Color
    @ViewBuilder var value: Value

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.m) {
            HStack(alignment: .center) {
                SymbolTile(symbol: symbol, color: color, size: 34)
                Spacer(minLength: 4)
                value
                    .font(.title2.weight(.bold))
                    .monospacedDigit()
            }
            Text(title)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        }
        .padding(Theme.Space.l)
        .frame(maxWidth: .infinity, alignment: .leading)
        .phoneCard()
        .contentShape(.rect(cornerRadius: PhoneCard.radius))
        .accessibilityElement(children: .combine)
    }
}

#endif
