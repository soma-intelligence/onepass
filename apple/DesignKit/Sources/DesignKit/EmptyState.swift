import SwiftUI

/// Empty list placeholder.
public struct EmptyState: View {
    private let title: String
    private let systemImage: String
    private let message: String

    public init(title: String, systemImage: String, message: String) {
        self.title = title
        self.systemImage = systemImage
        self.message = message
    }

    public var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: systemImage)
        } description: {
            Text(message)
        }
    }
}

#Preview("EmptyState") {
    EmptyState(
        title: "Aucun élément", systemImage: "tray",
        message: "Les éléments du coffre Projet Atlas apparaîtront ici.")
}
