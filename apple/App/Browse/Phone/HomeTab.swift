#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Accueil (spec 6.2, mockup `PhoneHome`): the account name, then Favoris and Récents (items
/// opened during this session, memory only, emptied on lock), each foldable, and "Nouvel élément".
/// "À proximité" opens the items placed within 2 km (the position is asked only once it is opened).
/// An empty vault shows "Créer ton premier élément".
struct HomeTab: View {
    @Environment(AppModel.self) private var model
    @AppStorage("onepass.home.favoritesOpen", store: AppModel.browseDefaults) private var favoritesOpen = true
    @AppStorage("onepass.home.recentsOpen", store: AppModel.browseDefaults) private var recentsOpen = true

    private var session: VaultSession { model.session }

    var body: some View {
        let favorites = session.items(filter: .favorites, query: "", sort: .title)
        let recents = recentItems
        Group {
            if session.counts().all == 0 {
                firstItemState
            } else {
                List {
                    SyncRefusalSection()
                    AccountChangedSection()
                    if !model.settings.displayName.isEmpty {
                        Text(model.settings.displayName)
                            .font(.title2.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .listRowBackground(Color.clear)
                            .listRowInsets(EdgeInsets(top: 0, leading: 6, bottom: 0, trailing: 6))
                    }
                    if model.showsAutoFillTip {
                        Section {
                            AutoFillTipCard()
                        }
                    }
                    HomeSection(
                        title: "Favoris", systemImage: "star.fill", color: .orange, isOpen: $favoritesOpen,
                        items: favorites, emptyText: "Touche l'étoile d'un élément pour le retrouver ici.",
                        id: "home.favorites")
                    HomeSection(
                        title: "Récents", systemImage: "clock.arrow.circlepath", color: .teal, isOpen: $recentsOpen,
                        items: recents, emptyText: "Les éléments ouverts apparaissent ici jusqu'au verrouillage.",
                        id: "home.recents")
                    Section {
                        NavigationLink(value: PhoneRoute.list(.nearby)) {
                            HStack(spacing: 12) {
                                NearbyTile(size: 32)
                                Text("À proximité").font(.headline)
                            }
                        }
                        .accessibilityIdentifier("home.nearby")
                    }
                    Section {
                        Button {
                            model.showNewItemPicker = true
                        } label: {
                            Label("Nouvel élément", systemImage: "plus")
                        }
                        .accessibilityIdentifier("home.newItem")
                    }
                }
                .listStyle(.insetGrouped)
                .listSectionSpacing(14)
                .contentMargins(.top, 4, for: .scrollContent)
            }
        }
        .navigationTitle("Accueil")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { PhoneRootToolbar() }
    }

    /// Recently opened items still present and active, newest first.
    private var recentItems: [FfiItemSummary] {
        let active = Dictionary(
            session.items(filter: .all, query: "", sort: .title).map { ($0.id, $0) },
            uniquingKeysWith: { first, _ in first })
        return session.recents.compactMap { active[$0] }
    }

    private var firstItemState: some View {
        ContentUnavailableView {
            Label("Ton coffre est vide", systemImage: "lock.shield")
        } description: {
            Text("Mots de passe, cartes, identités, notes : tout ce que tu ranges ici est chiffré sur tes appareils.")
        } actions: {
            Button("Créer ton premier élément") { model.showNewItemPicker = true }
                .buttonStyle(.glassProminent)
                .accessibilityIdentifier("home.firstItem")
        }
    }
}

/// One foldable block of the home screen: colored disc, title and count, then its items.
private struct HomeSection: View {
    let title: LocalizedStringKey
    let systemImage: String
    let color: Color
    @Binding var isOpen: Bool
    let items: [FfiItemSummary]
    let emptyText: LocalizedStringKey
    let id: String

    var body: some View {
        Section {
            Button {
                withAnimation(.snappy) { isOpen.toggle() }
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: systemImage)
                        .font(.system(size: 15, weight: .bold))
                        .foregroundStyle(.white)
                        .frame(width: 32, height: 32)
                        .background(color, in: Circle())
                    Text(title)
                        .font(.headline)
                        .foregroundStyle(.primary)
                    if !items.isEmpty {
                        Text(items.count, format: .number)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    }
                    Spacer()
                    Image(systemName: "chevron.down")
                        .font(.footnote.weight(.bold))
                        .foregroundStyle(.tint)
                        .rotationEffect(.degrees(isOpen ? 0 : -90))
                }
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
                } else {
                    ForEach(items, id: \.id) { summary in
                        NavigationLink(value: PhoneRoute.item(ItemRef(vaultID: summary.vaultId, itemID: summary.id))) {
                            ItemListRow(summary: summary, vaultName: nil)
                        }
                    }
                }
            }
        }
    }
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
