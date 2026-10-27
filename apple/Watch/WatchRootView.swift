import CompanionLink
import SwiftUI

/// Chooses the screen from the vault state.
struct WatchRootView: View {
    let model: any WatchEntriesModel

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("OnePass")
        }
    }

    @ViewBuilder
    private var content: some View {
        switch model.state {
        case .needsPasscode:
            WatchMessageView(
                systemImage: "lock.trianglebadge.exclamationmark",
                message: "Active un code sur ton Apple Watch pour utiliser OnePass"
            )
        case .closed:
            WatchMessageView(
                systemImage: "lock.shield",
                message: "Déverrouille ton Apple Watch pour ouvrir OnePass."
            )
        case .waitingForPhone:
            WatchMessageView(
                systemImage: "iphone.and.arrow.forward",
                message: "Marque des éléments « Sur l'Apple Watch » dans OnePass sur ton iPhone."
            )
        case .ready:
            if model.entries.isEmpty {
                WatchMessageView(
                    systemImage: "applewatch",
                    message: "Marque des éléments « Sur l'Apple Watch » dans OnePass sur ton iPhone."
                )
            } else {
                EntryListView(model: model)
            }
        }
    }
}

/// A centered glyph and one sentence (empty, passcode and closed states).
struct WatchMessageView: View {
    let systemImage: String
    let message: LocalizedStringKey

    var body: some View {
        ScrollView {
            VStack(spacing: 10) {
                Image(systemName: systemImage)
                    .font(.title2)
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
                Text(message)
                    .font(.footnote)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity)
            .padding(.top, 8)
        }
    }
}
