import SwiftUI

/// A concealed field: masked until tapped, masked again after 30 s or when the view goes away.
struct ConcealedValueView: View {
    let value: String
    @State private var revealed = false
    @State private var remask: Task<Void, Never>?

    var body: some View {
        Button {
            revealed ? hide() : reveal()
        } label: {
            HStack {
                Text(revealed ? value : "••••••••")
                    .font(.body.monospaced())
                    .lineLimit(revealed ? nil : 1)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Image(systemName: revealed ? "eye.slash" : "eye")
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            }
        }
        .buttonStyle(.plain)
        .accessibilityLabel(revealed ? Text(value) : Text("Masqué"))
        .accessibilityHint(revealed ? Text("Touche pour masquer") : Text("Touche pour révéler"))
        .onDisappear(perform: hide)
    }

    private func reveal() {
        revealed = true
        remask?.cancel()
        remask = Task { @MainActor in
            try? await Task.sleep(for: .seconds(30))
            guard !Task.isCancelled else { return }
            revealed = false
        }
    }

    private func hide() {
        remask?.cancel()
        remask = nil
        revealed = false
    }
}
