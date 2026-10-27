import SwiftUI

/// Empty list placeholder.
public struct EmptyState: View {
    private let title: String
    private let systemImage: String
    private let message: String
    private let actionTitle: String?
    private let actionIdentifier: String?
    private let action: (() -> Void)?

    public init(title: String, systemImage: String, message: String) {
        self.title = title
        self.systemImage = systemImage
        self.message = message
        actionTitle = nil
        actionIdentifier = nil
        action = nil
    }

    /// With a button under the message (for example "Nouvel élément" in an empty vault).
    public init(
        title: String, systemImage: String, message: String, actionTitle: String, actionIdentifier: String,
        action: @escaping () -> Void
    ) {
        self.title = title
        self.systemImage = systemImage
        self.message = message
        self.actionTitle = actionTitle
        self.actionIdentifier = actionIdentifier
        self.action = action
    }

    public var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: systemImage)
        } description: {
            Text(message)
        } actions: {
            if let actionTitle, let action {
                Button(action: action) {
                    Label(actionTitle, systemImage: "plus")
                }
                #if os(visionOS)
                // No Liquid Glass button styles on visionOS: the bordered style draws on the window's glass.
                .buttonStyle(.borderedProminent)
                #else
                .buttonStyle(.glassProminent)
                #endif
                .accessibilityIdentifier(actionIdentifier ?? "emptyState.action")
            }
        }
    }
}

#Preview("EmptyState") {
    EmptyState(
        title: "Aucun élément", systemImage: "tray",
        message: "Les éléments du coffre Projet Atlas apparaîtront ici.")
}
