import CompanionLink
import DesignKit
import OnePassCore
import SwiftUI

/// One entry: live TOTP code (when present) and its fields.
struct EntryDetailView: View {
    let model: any WatchEntriesModel
    let entry: FfiCompanionEntry

    var body: some View {
        List {
            if entry.hasTotp {
                Section {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let code = model.code(for: entry.itemId, at: context.date)
                        VStack(spacing: 6) {
                            Text(code.map { TotpFormat.grouped($0.code) } ?? "--- ---")
                                .font(.title2.weight(.semibold))
                                .monospacedDigit()
                                .lineLimit(1)
                                .minimumScaleFactor(0.5)
                            if let code {
                                // The watch's own ring (DesignKit has a larger one by the same name).
                                OnePassWatch.TotpRing(remaining: code.remaining, period: code.period)
                                    .frame(width: 28, height: 28)
                            }
                        }
                        .frame(maxWidth: .infinity)
                        .accessibilityElement(children: .combine)
                    }
                } header: {
                    Text("entryDetailView.code")
                }
            }
            ForEach(Array(entry.fields.enumerated()), id: \.offset) { _, field in
                Section {
                    FieldValue(field: field)
                } header: {
                    Text(field.label)
                }
            }
        }
        .safeAreaInset(edge: .top, spacing: 0) { identityBand }
        .navigationTitle(entry.title)
    }

    /// A thin wash in the entry's category color under the title. The watch has no site icons, so
    /// the category decides. Flat fallback is no band at all.
    private var identityBand: some View {
        let color = IdentityTint.color(
            brand: nil, siteIcon: nil, category: ItemCategory.of(entry.itemType).color)
        return Color.clear
            .frame(height: 6)
            .frame(maxWidth: .infinity)
            .washBackground(Theme.Wash.identity(color, dark: true), flat: .clear, in: Rectangle())
            .allowsHitTesting(false)
            .accessibilityHidden(true)
    }
}

private struct FieldValue: View {
    let field: FfiCompanionField

    var body: some View {
        switch field.kind {
        case .text:
            Text(field.value)
                .fixedSize(horizontal: false, vertical: true)
        case .concealed:
            ConcealedValueView(value: field.value)
        case .barcode:
            // Graphic rendering is deferred (ruling W8): large fixed-width text.
            Text(field.value)
                .font(.title3.monospaced().weight(.semibold))
                .minimumScaleFactor(0.5)
                .lineLimit(2)
                .frame(maxWidth: .infinity)
        }
    }
}
