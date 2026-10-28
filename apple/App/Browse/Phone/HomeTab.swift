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
    @AppStorage("onepass.home.favoritesOpen", store: AppModel.browseDefaults) private var favoritesOpen = true
    @AppStorage("onepass.home.recentsOpen", store: AppModel.browseDefaults) private var recentsOpen = true
    @AppStorage("onepass.home.showsNearby", store: AppModel.browseDefaults) private var showsNearby = true
    @AppStorage("onepass.home.showsProfile", store: AppModel.browseDefaults) private var showsProfile = true
    @AppStorage("onepass.home.showsFavorites", store: AppModel.browseDefaults) private var showsFavorites = true
    @AppStorage("onepass.home.showsRecents", store: AppModel.browseDefaults) private var showsRecents = true

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
                    VStack(alignment: .leading, spacing: 16) {
                        Text(accountName)
                            .font(.title2.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .padding(.horizontal, 4)
                            .accessibilityAddTraits(.isHeader)
                        // Banners: these are list sections elsewhere, plain blocks here.
                        SyncRefusalSection()
                        AccountChangedSection()
                        if model.showsAutoFillTip {
                            AutoFillTipCard()
                                .padding(16)
                                .phoneCard()
                        }
                        if showsNearby { HomeNearbyCard() }
                        if showsProfile, let profile { HomeProfileCard(summary: profile) }
                        if showsFavorites {
                            HomeListCard(
                                title: "Favoris", symbol: "star.fill", color: .orange, isOpen: $favoritesOpen,
                                items: favorites, list: .favorites,
                                emptyText: "Touche l'étoile d'un élément pour le retrouver ici.", id: "home.favorites")
                        }
                        if showsRecents {
                            HomeListCard(
                                title: "Récents", symbol: "clock.fill", color: Color(white: 0.55), isOpen: $recentsOpen,
                                items: recents, list: nil,
                                emptyText: "Les éléments ouverts apparaissent ici jusqu'au verrouillage.", id: "home.recents")
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.bottom, 24)
                }
                .background(PhoneBackground())
            }
        }
        .navigationTitle("Accueil")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            PhoneRootToolbar {
                Section("Afficher sur l'accueil") {
                    Toggle("À proximité", systemImage: "location", isOn: $showsNearby)
                    Toggle("Profil", systemImage: "person.crop.circle", isOn: $showsProfile)
                    Toggle("Favoris", systemImage: "star", isOn: $showsFavorites)
                    Toggle("Récents", systemImage: "clock", isOn: $showsRecents)
                }
            }
        }
    }

    private var accountName: String {
        model.settings.displayName.isEmpty ? String(localized: "Mon compte") : model.settings.displayName
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
        VStack(spacing: 18) {
            Spacer()
            HStack(spacing: -10) {
                ForEach(Array([FfiItemType.login, .creditCard, .identity, .secureNote].enumerated()), id: \.offset) { i, type in
                    CategoryArtwork(type: type, size: 64)
                        .rotationEffect(.degrees(Double(i) * 8 - 12))
                        .shadow(color: .black.opacity(0.18), radius: 6, y: 3)
                }
            }
            .padding(.bottom, 6)
            Text("Ton coffre est vide")
                .font(.title2.weight(.bold))
            Text("Mots de passe, cartes, identités, notes : tout ce que tu ranges ici est chiffré sur tes appareils.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Button {
                model.showNewItemPicker = true
            } label: {
                Text("Créer ton premier élément")
                    .font(.headline)
                    .padding(.horizontal, 8)
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
        HStack(spacing: 12) {
            Button(action: toggle) {
                HStack(spacing: 12) {
                    tile
                    VStack(alignment: .leading, spacing: 1) {
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
            .accessibilityValue(isOpen ? Text("Déplié") : Text("Replié"))
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
            .accessibilityLabel(isOpen ? Text("Replier") : Text("Déplier"))
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 4)
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
                            Label("Voir les éléments", systemImage: "list.bullet")
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
                    .accessibilityLabel(Text("Actions pour \(Text(title))"))
                }
            }
            if isOpen {
                Group {
                    if items.isEmpty {
                        Text(emptyText)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 16)
                            .padding(.bottom, 14)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        Divider().padding(.leading, 58)
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
            HStack(spacing: 12) {
                Image(systemName: "person.fill")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 30, height: 30)
                    .background(Color.blue, in: Circle())
                VStack(alignment: .leading, spacing: 1) {
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
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .contentShape(.rect)
        }
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
                        Picker("Rayon", selection: $radius) {
                            ForEach(Self.radii, id: \.self) { Text(verbatim: Self.label($0)).tag($0) }
                        }
                    } label: {
                        HStack(spacing: 3) {
                            Text(verbatim: Self.label(radius))
                            Image(systemName: "chevron.up.chevron.down").font(.caption2.weight(.semibold))
                        }
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .frame(minHeight: 44)
                        .contentShape(.rect)
                    }
                    .accessibilityLabel(Text("Rayon"))
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
                    .accessibilityLabel(showsMap ? Text("Masquer la carte") : Text("Afficher la carte"))
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
                        .clipShape(.rect(cornerRadius: 12, style: .continuous))
                        .padding(.horizontal, 14)
                        .padding(.bottom, 10)
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
            ? String(localized: "Rien dans un rayon de \(Self.label(radius))")
            : String(localized: "\(count) dans un rayon de \(Self.label(radius))")
    }

    @ViewBuilder private var content: some View {
        switch nearby.phase {
        case .ready:
            if !nearby.items.isEmpty {
                Divider().padding(.leading, 58)
                PhoneItemRows(
                    items: nearby.items.map(\.summary), vaultName: { _ in nil },
                    pill: { summary in
                        nearby.items.first { $0.summary.id == summary.id }.map { Self.pill($0.distance) }
                    })
            }
        case .idle, .locating:
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Recherche de ta position…").font(.subheadline).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.bottom, 14)
        case .failed(.denied):
            VStack(alignment: .leading, spacing: 8) {
                Text("Autorise OnePass à utiliser ta position pour voir les éléments enregistrés autour de toi. Elle reste sur cet appareil.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Button("Ouvrir les Réglages") { LocationAccess.openSettings() }
                    .font(.subheadline.weight(.semibold))
                    .accessibilityIdentifier("home.nearby.openSettings")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.bottom, 14)
        case .failed(.unavailable):
            HStack {
                Text("Impossible de savoir où tu es pour le moment.").font(.subheadline).foregroundStyle(.secondary)
                Spacer()
                Button("Réessayer") { Task { await nearby.load(model.session, within: radius) } }
                    .font(.subheadline.weight(.semibold))
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 14)
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
                    HStack(spacing: 8) {
                        ItemListRow(summary: summary, vaultName: vaultName(summary.vaultId))
                        if let pill = pill(summary) {
                            Text(verbatim: pill)
                                .font(.caption.weight(.medium))
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, 7)
                                .padding(.vertical, 3)
                                .background(Color.primary.opacity(0.08), in: Capsule())
                        }
                        Image(systemName: "chevron.forward")
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(.tertiary)
                            .accessibilityHidden(true)
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 7)
                    .contentShape(Rectangle())
                }
                .buttonStyle(RowHighlightButtonStyle())
                // The hairline belongs to the row below it, so a row leaving takes its own line along.
                .overlay(alignment: .top) {
                    if index > 0 { Divider().padding(.leading, 62) }
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
    static let radius: CGFloat = 18
}

extension View {
    func phoneCard() -> some View {
        let shape = RoundedRectangle(cornerRadius: PhoneCard.radius, style: .continuous)
        return background(Color(uiColor: .secondarySystemGroupedBackground), in: shape)
            .clipShape(shape)
            .overlay { shape.strokeBorder(Color.primary.opacity(0.06)) }
    }
}

/// The screen behind the iPhone cards: the grouped background, plain. The cards and the glass bars
/// carry the depth; a tinted wash on top read as decoration.
struct PhoneBackground: View {
    var body: some View {
        Color(uiColor: .systemGroupedBackground)
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
                VStack(alignment: .leading, spacing: 8) {
                    IntegrityBanner(kind: kind)
                    Text("Les données reçues d'iCloud ont été refusées. Tes modifications restent sur cet appareil mais ne se synchronisent plus pour ce coffre.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Button("Voir les solutions") { safeExitKind = kind }
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
#endif
