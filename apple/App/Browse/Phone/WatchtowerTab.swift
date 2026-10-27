#if os(iOS)
import DesignKit
import SwiftUI

/// Watchtower (spec 6.2, ruling R20): the tab keeps the mockup's navigation and announces
/// milestone 5. No figure, no fake data.
struct WatchtowerTab: View {
    var body: some View {
        EmptyState(
            title: String(localized: "Watchtower arrive bientôt"), systemImage: "checkmark.shield",
            message: String(localized: """
                Watchtower te signalera les comptes touchés par une fuite de données, les mots de passe \
                faibles ou réutilisés et les éléments qui arrivent à échéance.
                """))
            .accessibilityIdentifier("watchtower.empty")
            .navigationTitle("Watchtower")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { PhoneRootToolbar() }
    }
}
#endif
