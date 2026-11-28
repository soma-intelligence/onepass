#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// The scan flow, full screen (`AppModel.scanRequest`): "Que veux-tu ajouter ?" for a new
/// document, or straight to the passport's camera for "Scanner la puce".
struct ScanCover: View {
    @Environment(AppModel.self) private var app
    let request: ScanRequest

    var body: some View {
        NavigationStack {
            switch request.target {
            case .new(let vaultID):
                ScanEntrySheet(vaultID: vaultID)
            case .merge:
                PassportScanFlow(target: request.target, session: app.session)
            }
        }
    }
}

/// "Que veux-tu ajouter ?" (spec 6.1): the documents Cleon can scan. P1 reads passports only, so
/// the other types are not listed yet.
struct ScanEntrySheet: View {
    @Environment(AppModel.self) private var app
    let vaultID: String
    @State private var scanning = false

    var body: some View {
        List {
            Section {
                Button {
                    scanning = true
                } label: {
                    HStack(spacing: Theme.Space.m) {
                        PassportCoverThumbnail(family: .passportGeneric, size: 44)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(ItemCategory.of(.passport).singular)
                                .font(.body.weight(.semibold))
                                .foregroundStyle(.primary)
                            Text("scan.entry.passportHint")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                        Spacer(minLength: 0)
                        Image(systemName: "chevron.right")
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(.tertiary)
                    }
                    .contentShape(.rect)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("scan.entry.passport")
            } header: {
                Text("browse.whatDoWantTo")
                    .font(.title2.weight(.bold))
                    .foregroundStyle(.primary)
                    .textCase(nil)
                    .padding(.bottom, Theme.Space.s)
            }
        }
        .navigationTitle(Text("scan.title.entry"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("common.close", systemImage: "xmark") { app.finishScan(nil) }
                    .accessibilityIdentifier("scan.close")
            }
        }
        .navigationDestination(isPresented: $scanning) {
            PassportScanFlow(target: .new(vaultID: vaultID), session: app.session)
        }
    }
}
#endif
