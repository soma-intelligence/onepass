import CompanionLink
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
                                TotpRing(remaining: code.remaining, period: code.period)
                                    .frame(width: 28, height: 28)
                            }
                        }
                        .frame(maxWidth: .infinity)
                        .accessibilityElement(children: .combine)
                    }
                } header: {
                    Text("Code")
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
        .navigationTitle(entry.title)
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
