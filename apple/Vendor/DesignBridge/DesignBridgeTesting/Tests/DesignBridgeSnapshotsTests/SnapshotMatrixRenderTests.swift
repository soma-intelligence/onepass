#if canImport(UIKit) && os(iOS)
import SnapshotTesting
import SwiftUI
import Testing
@testable import DesignBridgeSnapshots

/// Renders the smoke matrix on an iOS simulator. Runs only under `xcodebuild test` with an iOS
/// destination; `swift test` on macOS skips it. References live in `__Snapshots__` next to this
/// file and were recorded on the iPhone 17e simulator, iOS 27.2.
@MainActor
@Suite("Snapshot matrix rendering", .snapshots(record: .missing))
struct SnapshotMatrixRenderTests {
    struct Sample: View {
        let title: String
        let detail: String

        var body: some View {
            VStack(alignment: .leading, spacing: 12) {
                Text(title).font(.title2.bold())
                Text(detail).font(.body).foregroundStyle(.secondary)
                Label(title, systemImage: "checkmark.circle.fill").font(.headline)
            }
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(Color(uiColor: .systemBackground))
        }
    }

    @Test func smokeMatrixRendersEveryCell() {
        snapshotMatrix(
            of: { variant in
                Sample(
                    title: variant.locale.text(variant.locale.id == "fr" ? "Réglages" : "Settings"),
                    detail: variant.locale.text(
                        variant.locale.id == "fr"
                            ? "Ton coffre est verrouillé. Déverrouille-le pour continuer."
                            : "Your vault is locked. Unlock it to continue."
                    )
                )
            },
            name: "sample",
            matrix: .smoke
        )
    }

    @Test func fixedViewOverloadUsesTheEnvironment() {
        snapshotMatrix(
            of: Sample(title: "Settings", detail: "Unlock to continue."),
            name: "fixed",
            matrix: SnapshotMatrix(devices: [.iPad], appearances: [.dark], contentSizes: [.accessibility5], locales: [.en])
        )
    }
}
#endif
