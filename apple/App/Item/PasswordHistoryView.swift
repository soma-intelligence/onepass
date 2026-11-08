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
            VStack(alignment: .leading, spacing: Theme.Space.m) {
                if let error {
                    Text(error).foregroundStyle(.red).padding(.horizontal, Theme.Space.l)
                }
                if !entries.isEmpty {
                    EditorCard {
                        ForEach(Array(entries.enumerated()), id: \.offset) { index, entry in
                            if index > 0 { CardDivider() }
                            ValueRow(
                                label: String(localized: "item.replaced \(FieldDates.timestamp(entry.replacedAt))"),
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
                Text("item.oldPasswordsStayEncrypted")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, Theme.Space.l)
            }
            .padding(.horizontal, Theme.Space.xl)
            .padding(.vertical, Theme.Space.xl)
            .frame(maxWidth: 760)
            .frame(maxWidth: .infinity)
        }
        .defaultScrollAnchor(.top)
        .navigationTitle("item.previousVersions")
        .overlay(alignment: .bottom) {
            if let toast {
                Text(toast)
                    .font(.footnote.weight(.medium))
                    .padding(.horizontal, Theme.Space.l)
                    .padding(.vertical, Theme.Space.s)
                    #if os(visionOS)
                    .glassBackgroundEffect(in: Capsule())
                    #else
                    .glassEffect(.regular, in: Capsule())
                    #endif
                    .padding(.bottom, Theme.Space.l)
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
        let text = String(localized: "app.copiedClearedIn90")
        withAnimation(.snappy) { toast = text }
        Task {
            try? await Task.sleep(for: .seconds(1.6))
            if toast == text { withAnimation(.snappy) { toast = nil } }
        }
    }
}
