import DesignKit
import SwiftUI
import VaultKit

/// Previous passwords of an item, newest first, masked with Révéler and Copier, in one card like the
/// detail. Loaded when shown, dropped when it goes away.
struct PasswordHistoryView: View {
    @Environment(AppModel.self) private var model
    #if os(iOS) || os(visionOS)
    @Environment(\.isSceneCaptured) private var captured
    #else
    private let captured = false
    #endif
    let ref: ItemRef
    @State private var entries: [FfiHistoryEntry] = []
    @State private var error: String?
    @State private var toast: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                if let error {
                    Text(error).foregroundStyle(.red).padding(.horizontal, 16)
                }
                if !entries.isEmpty {
                    EditorCard {
                        ForEach(Array(entries.enumerated()), id: \.offset) { index, entry in
                            if index > 0 { CardDivider() }
                            ValueRow(
                                label: String(localized: "remplacé le \(FieldDates.timestamp(entry.replacedAt))"),
                                value: entry.value, isSecret: true, monospaced: true,
                                copyIdentifier: "history.copy.\(index)", allowsLarge: false,
                                concealToken: model.session.concealGeneration, captured: captured,
                                onCopy: { copy(entry.value) },
                                onReveal: { _ in model.session.noteActivity() }
                            ) {
                                EmptyView()
                            }
                            .privacySensitive()
                        }
                    }
                }
                Text("Les anciens mots de passe restent chiffrés avec l'élément.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 16)
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 20)
            .frame(maxWidth: 760)
            .frame(maxWidth: .infinity)
        }
        .defaultScrollAnchor(.top)
        .navigationTitle("Versions précédentes")
        .overlay(alignment: .bottom) {
            if let toast {
                Text(toast)
                    .font(.footnote.weight(.medium))
                    .padding(.horizontal, 14)
                    .padding(.vertical, 9)
                    #if os(visionOS)
                    .glassBackgroundEffect(in: Capsule())
                    #else
                    .glassEffect(.regular, in: Capsule())
                    #endif
                    .padding(.bottom, 18)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .task {
            do {
                entries = try await model.session.passwordHistory(vaultID: ref.vaultID, itemID: ref.itemID)
                    .sorted { $0.replacedAt > $1.replacedAt }
            } catch {
                self.error = VaultError(error).localizedMessage
            }
        }
        .onDisappear { entries = [] }
    }

    private func copy(_ value: String) {
        model.session.copy(value, concealed: true)
        let text = String(localized: "Copié · effacé dans 90 s")
        withAnimation(.snappy) { toast = text }
        Task {
            try? await Task.sleep(for: .seconds(1.6))
            if toast == text { withAnimation(.snappy) { toast = nil } }
        }
    }
}
