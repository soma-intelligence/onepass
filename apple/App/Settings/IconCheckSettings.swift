#if DEBUG
import SwiftUI
import VaultKit
#if os(macOS)
import AppKit
#else
import UIKit
#endif

extension IconSource {
    /// The French label of a source in the report.
    var label: LocalizedStringKey {
        switch self {
        case .chosen: "Choisie"
        case .pack: "Pack"
        case .parentBrand: "Marque mère"
        case .site: "Site"
        case .monogram: "Monogramme"
        }
    }
}

/// Debug > "Icônes à vérifier": every login of the unlocked vaults with the source of its icon, the
/// doubtful ones (monogram, site) first, so the owner can flag a wrong logo. Reads the caches only:
/// no request. "Copier" puts the shown rows on the clipboard as plain text and sends nothing.
struct IconCheckSettings: View {
    @Environment(AppModel.self) private var model
    @State private var rows: [IconSourceReport.Row] = []
    @State private var filter: IconSource?

    private var shown: [IconSourceReport.Row] {
        guard let filter else { return rows }
        return rows.filter { $0.source == filter }
    }

    var body: some View {
        let shown = self.shown
        Form {
            Section {
                Picker("Source", selection: $filter) {
                    Text("Toutes").tag(IconSource?.none)
                    ForEach(IconSource.allCases, id: \.self) { source in
                        Text(source.label).tag(IconSource?.some(source))
                    }
                }
                .accessibilityIdentifier("settings.iconCheck.filter")
                LabeledContent("Identifiants") {
                    Text(verbatim: "\(shown.count)")
                }
                Button("Copier") { copy(shown) }
                    .disabled(shown.isEmpty)
                    .accessibilityIdentifier("settings.iconCheck.copy")
            }
            Section {
                if shown.isEmpty {
                    Text("Aucun identifiant à afficher")
                        .foregroundStyle(.secondary)
                }
                ForEach(Array(shown.enumerated()), id: \.offset) { _, row in
                    LabeledContent {
                        Text(row.source.label)
                    } label: {
                        Text(verbatim: row.title)
                        if !row.domain.isEmpty {
                            Text(verbatim: row.domain)
                        }
                    }
                }
            }
        }
        .settingsPage("Icônes à vérifier")
        .task { await reload() }
    }

    private func reload() async {
        rows = await IconSourceReport.report(model.session.summaries, resolver: model.iconLoader)
    }

    /// One line per row, `domain<TAB>title<TAB>source`.
    private func copy(_ rows: [IconSourceReport.Row]) {
        let text = IconSourceReport.text(rows)
        #if os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        #else
        UIPasteboard.general.string = text
        #endif
    }
}
#endif
