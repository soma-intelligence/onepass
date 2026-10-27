#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Accueil (spec 6.2, mockup `PhoneHome`), in the Mac's design: four tiles as the top of the Mac
/// sidebar (Tous les éléments, Favoris, Watchtower, À proximité), the AutoFill tip, then two
/// foldable cards: Favoris and Récents (items opened during this session, memory only, emptied on
/// lock). "À proximité" asks for the position only once it is opened. An empty vault shows "Créer
/// ton premier élément".
struct HomeTab: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openPhoneTab) private var openTab
    @AppStorage("onepass.home.favoritesOpen", store: AppModel.browseDefaults) private var favoritesOpen = true
    @AppStorage("onepass.home.recentsOpen", store: AppModel.browseDefaults) private var recentsOpen = true

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
                    VStack(alignment: .leading, spacing: 20) {
                        // Banners: these are list sections elsewhere, plain blocks here.
                        SyncRefusalSection()
                        AccountChangedSection()
                        tiles(all: counts.all, favorites: counts.favorites)
                        if model.showsAutoFillTip {
                            AutoFillTipCard()
                                .padding(16)
                                .phoneCard()
                        }
                        HomeSection(
                            title: "favoris", isOpen: $favoritesOpen, items: favorites,
                            emptyText: "Touche l'étoile d'un élément pour le retrouver ici.", id: "home.favorites")
                        HomeSection(
                            title: "récents", isOpen: $recentsOpen, items: recents,
                            emptyText: "Les éléments ouverts apparaissent ici jusqu'au verrouillage.", id: "home.recents")
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 8)
                    .padding(.bottom, 24)
                }
                .background(PhoneBackground())
            }
        }
        .navigationTitle(greeting)
        .navigationBarTitleDisplayMode(.large)
        .toolbar { PhoneRootToolbar() }
    }

    /// "Accueil", or the account's first name when there is one.
    private var greeting: String {
        let first = model.settings.displayName.split(separator: " ").first.map(String.init) ?? ""
        return first.isEmpty ? String(localized: "Accueil") : String(localized: "Bonjour \(first)")
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
                        Text("2 km").font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
                    }
                }
                .accessibilityIdentifier("home.nearby")
            }
        }
        .buttonStyle(.plain)
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

/// One of the four tiles of Accueil: the Mac sidebar's colored tile, the figure on the right, the
/// name below.
private struct HomeTile<Value: View>: View {
    let title: LocalizedStringKey
    let symbol: String
    let color: Color
    @ViewBuilder var value: Value

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
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
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .phoneCard()
        .contentShape(.rect(cornerRadius: PhoneCard.radius))
        .accessibilityElement(children: .combine)
    }
}

/// One foldable card of the home screen: small accent label, count and chevron, then its items.
private struct HomeSection: View {
    let title: LocalizedStringKey
    @Binding var isOpen: Bool
    let items: [FfiItemSummary]
    let emptyText: LocalizedStringKey
    let id: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                withAnimation(.snappy) { isOpen.toggle() }
            } label: {
                HStack(spacing: 8) {
                    PhoneSectionLabel(title)
                    if !items.isEmpty {
                        Text(items.count, format: .number)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    }
                    Spacer()
                    Image(systemName: "chevron.down")
                        .font(.footnote.weight(.bold))
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(isOpen ? 0 : -90))
                }
                .padding(.horizontal, 6)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityAddTraits(.isHeader)
            .accessibilityValue(isOpen ? Text("Déplié") : Text("Replié"))
            .accessibilityIdentifier(id)
            if isOpen {
                if items.isEmpty {
                    Text(emptyText)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .padding(16)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .phoneCard()
                } else {
                    PhoneItemRows(items: items, vaultName: { _ in nil })
                }
            }
        }
    }
}

/// Item rows in one card (Accueil): the list rows of the Mac, a chevron, hairlines between rows.
struct PhoneItemRows: View {
    let items: [FfiItemSummary]
    let vaultName: (String) -> String?

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(items.enumerated()), id: \.element.id) { index, summary in
                if index > 0 { Divider().padding(.leading, 62) }
                NavigationLink(value: PhoneRoute.item(ItemRef(vaultID: summary.vaultId, itemID: summary.id))) {
                    HStack(spacing: 8) {
                        ItemListRow(summary: summary, vaultName: vaultName(summary.vaultId))
                        Image(systemName: "chevron.forward")
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(.tertiary)
                            .accessibilityHidden(true)
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 7)
                    .contentShape(Rectangle())
                }
                .buttonStyle(PhoneRowButtonStyle())
            }
        }
        .phoneCard()
    }
}

/// A row that highlights while pressed, like a list row.
struct PhoneRowButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(configuration.isPressed ? Color.primary.opacity(0.08) : .clear)
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

/// The screen behind the iPhone cards: the grouped background with a faint accent glow on top, the
/// iPhone's take on the Mac window glass.
struct PhoneBackground: View {
    var body: some View {
        Color(uiColor: .systemGroupedBackground)
            .overlay(alignment: .top) {
                LinearGradient(
                    colors: [Theme.accent.opacity(0.10), Theme.accent.opacity(0)],
                    startPoint: .top, endPoint: .bottom)
                    .frame(height: 320)
            }
            .ignoresSafeArea()
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
