import CompanionLink
import OnePassCore
import SwiftUI

/// Two sections: "Codes" (entries with a TOTP, code shown live) and "Éléments" (the rest).
struct EntryListView: View {
    let model: any WatchEntriesModel

    private var codes: [FfiCompanionEntry] { model.entries.filter(\.hasTotp) }
    private var items: [FfiCompanionEntry] { model.entries.filter { !$0.hasTotp } }

    var body: some View {
        List {
            if !codes.isEmpty {
                Section("Codes") {
                    ForEach(codes, id: \.itemId) { entry in
                        NavigationLink {
                            EntryDetailView(model: model, entry: entry)
                        } label: {
                            CodeRow(model: model, entry: entry)
                        }
                    }
                }
            }
            if !items.isEmpty {
                Section("Éléments") {
                    ForEach(items, id: \.itemId) { entry in
                        NavigationLink {
                            EntryDetailView(model: model, entry: entry)
                        } label: {
                            ItemRow(entry: entry)
                        }
                    }
                }
            }
        }
    }
}

/// Title, large grouped code and the countdown ring.
private struct CodeRow: View {
    let model: any WatchEntriesModel
    let entry: FfiCompanionEntry

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let code = model.code(for: entry.itemId, at: context.date)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.title)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                HStack(alignment: .center, spacing: 6) {
                    Text(code.map { TotpFormat.grouped($0.code) } ?? "--- ---")
                        .font(.title3.weight(.semibold))
                        .monospacedDigit()
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                    Spacer(minLength: 0)
                    if let code {
                        TotpRing(remaining: code.remaining, period: code.period)
                            .frame(width: 22, height: 22)
                    }
                }
            }
            .accessibilityElement(children: .combine)
        }
    }
}

private struct ItemRow: View {
    let entry: FfiCompanionEntry

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: ItemSymbol.name(for: entry.itemType))
                .foregroundStyle(.tint)
                .frame(width: 20)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(entry.title).lineLimit(1)
                if !entry.subtitle.isEmpty {
                    Text(entry.subtitle)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
        }
    }
}

enum TotpFormat {
    /// "123456" becomes "123 456", "12345678" becomes "123 456 78".
    static func grouped(_ code: String) -> String {
        var out = ""
        for (index, character) in code.enumerated() {
            if index > 0, index % 3 == 0 { out.append(" ") }
            out.append(character)
        }
        return out
    }
}

enum ItemSymbol {
    static func name(for type: FfiItemType) -> String {
        switch type {
        case .login, .password: "key.fill"
        case .router: "wifi.router"
        case .creditCard: "creditcard.fill"
        case .bankAccount: "building.columns.fill"
        case .membership, .rewardProgram: "person.text.rectangle.fill"
        case .identity, .idCard, .passport, .driverLicense: "person.crop.square.fill"
        case .accessCode: "number.square.fill"
        case .server, .database: "server.rack"
        case .email: "envelope.fill"
        default: "lock.fill"
        }
    }
}
