#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Watchtower on iPhone: the Mac page in one column. The score gauge on top, the password
/// strength, one card per check ("Voir les éléments" pushes the flagged items), then the breach
/// setting. Everything comes from the core's report (`WatchtowerModel`); nothing is shown before it.
struct WatchtowerTab: View {
    @Environment(AppModel.self) private var model

    private var watchtower: WatchtowerModel { model.watchtower }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                VStack(spacing: 10) {
                    ScoreGauge(score: watchtower.report.map { Int($0.score) })
                        .padding(.top, 6)
                    Text("Watchtower repère les mots de passe à changer et les sites où tu peux renforcer la sécurité de tes comptes.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                    statusLine
                }
                .frame(maxWidth: .infinity)
                .padding(.bottom, 4)
                if let report = watchtower.report {
                    StrengthCard(levels: report.strength.map(Int.init))
                    ForEach(WatchtowerCard.all) { card in
                        let ids = card.itemIDs(in: report)
                        WatchtowerCardView(card: card, report: report, checkBreaches: watchtower.checkBreaches) {}
                            .overlay {
                                // The card's own button shows the items in the Mac list column:
                                // here, a pushed list of the flagged items.
                                NavigationLink(value: PhoneRoute.watchtower(title: card.title, itemIDs: ids)) {
                                    Color.clear
                                }
                                .disabled(ids.isEmpty)
                                .accessibilityLabel(Text("Voir les éléments"))
                                .accessibilityIdentifier("watchtower.show.\(card.id)")
                            }
                    }
                }
                BreachSettingCard()
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 24)
        }
        .background(PhoneBackground())
        .navigationTitle("Watchtower")
        .navigationBarTitleDisplayMode(.large)
        .toolbar {
            PhoneRootToolbar()
        }
        .refreshable { watchtower.refresh(model.session) }
        .task(id: model.session.summariesRevision) { watchtower.refreshIfNeeded(model.session) }
        .onChange(of: watchtower.checkBreaches) { watchtower.refreshIfNeeded(model.session) }
        .onChange(of: model.session.hiddenVaultIDs) { watchtower.refreshIfNeeded(model.session) }
        .accessibilityIdentifier("page.watchtower")
    }

    @ViewBuilder private var statusLine: some View {
        switch watchtower.phase {
        case .idle, .ready:
            if let report = watchtower.report {
                Text(report.itemsAnalyzed == 1
                     ? String(localized: "1 élément analysé") : String(localized: "\(report.itemsAnalyzed) éléments analysés"))
                    .font(.footnote)
                    .foregroundStyle(.tertiary)
            }
        case .analyzing:
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Analyse des éléments…").font(.footnote).foregroundStyle(.secondary)
            }
        case .checkingBreaches(let done, let total):
            HStack(spacing: 8) {
                ProgressView(value: Double(done), total: Double(max(total, 1))).frame(width: 120)
                Text("Vérification des fuites : \(done) sur \(total)").font(.footnote).foregroundStyle(.secondary)
            }
        case .failed(let message):
            Label(message, systemImage: "exclamationmark.triangle.fill")
                .font(.footnote)
                .foregroundStyle(.orange)
        }
    }
}

/// The items a Watchtower card flagged, pushed from the Watchtower tab.
struct WatchtowerItemsList: View {
    @Environment(AppModel.self) private var model
    let title: String
    let itemIDs: Set<String>

    var body: some View {
        let items = model.session.items(filter: .all, query: "", sort: .title).filter { itemIDs.contains($0.id) }
        let showVault = model.session.vaults.count > 1
        List {
            ForEach(items, id: \.id) { summary in
                NavigationLink(value: PhoneRoute.item(ItemRef(vaultID: summary.vaultId, itemID: summary.id))) {
                    ItemListRow(
                        summary: summary,
                        vaultName: showVault ? model.session.allVaults.first { $0.id == summary.vaultId }?.meta.name : nil)
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(PhoneBackground())
        .overlay {
            if items.isEmpty {
                EmptyState(title: String(localized: "Rien à signaler"), systemImage: "checkmark.shield",
                    message: String(localized: "Aucun élément concerné pour l'instant."))
            }
        }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.large)
    }
}
#endif
