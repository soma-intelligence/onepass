import SwiftUI
import os

/// A text whose rendered size is smaller than the size it wants (UX-TEXT-01).
public struct DBTruncationReport: Sendable, Equatable, Identifiable {
    public enum Kind: String, Sendable {
        /// Lines are lost: the wrapped text is taller than its frame.
        case clipped
        /// A single line is narrower than the text: truncated with an ellipsis or scaled down.
        case compressed
    }

    public let id: String
    public let kind: Kind
    public let actualSize: CGSize
    /// Size when free to wrap at the actual width.
    public let wrappedIdealSize: CGSize
    /// Size on one line with no width limit.
    public let singleLineIdealSize: CGSize

    /// The pure check. Returns nil when the text shows in full.
    public static func evaluate(
        id: String,
        actual: CGSize,
        wrappedIdeal: CGSize,
        singleLineIdeal: CGSize,
        tolerance: CGFloat = 0.5
    ) -> DBTruncationReport? {
        guard actual.width > 0, actual.height > 0 else { return nil }
        if wrappedIdeal.height > actual.height + tolerance {
            return DBTruncationReport(id: id, kind: .clipped, actualSize: actual, wrappedIdealSize: wrappedIdeal, singleLineIdealSize: singleLineIdeal)
        }
        let isSingleLine = actual.height < singleLineIdeal.height * 1.5
        if isSingleLine, singleLineIdeal.width > actual.width + tolerance {
            return DBTruncationReport(id: id, kind: .compressed, actualSize: actual, wrappedIdealSize: wrappedIdeal, singleLineIdealSize: singleLineIdeal)
        }
        return nil
    }
}

/// Collects truncation reports up the view tree.
public struct DBTruncationPreferenceKey: PreferenceKey {
    public static let defaultValue: [DBTruncationReport] = []

    public static func reduce(value: inout [DBTruncationReport], nextValue: () -> [DBTruncationReport]) {
        value.append(contentsOf: nextValue())
    }
}

public extension View {
    /// Debug only: measures this text against its ideal size, outlines it in
    /// red when truncated, and publishes a `DBTruncationReport` through
    /// `DBTruncationPreferenceKey`. A no-op in release builds.
    ///
    /// The ideal sizes come from hidden copies of the view, so put the probe
    /// on a `Text` or a small label, not on a stateful container.
    @ViewBuilder
    func dbTruncationProbe(_ id: String, outline: Bool = true) -> some View {
        #if DEBUG
        modifier(DBTruncationProbeModifier(id: id, outline: outline))
        #else
        self
        #endif
    }

    /// Debug only: receives every report from probes below. A no-op in release.
    @ViewBuilder
    func dbTruncationMonitor(_ action: @escaping @MainActor ([DBTruncationReport]) -> Void) -> some View {
        #if DEBUG
        onPreferenceChange(DBTruncationPreferenceKey.self) { reports in
            MainActor.assumeIsolated { action(reports) }
        }
        #else
        self
        #endif
    }

    /// Debug only: logs every truncation report below to the unified log
    /// (subsystem `DesignBridgeKit`, category `Truncation`).
    func dbTruncationLogging() -> some View {
        dbTruncationMonitor { reports in
            let logger = Logger(subsystem: "DesignBridgeKit", category: "Truncation")
            for report in reports {
                logger.warning("\(report.kind.rawValue, privacy: .public) text '\(report.id, privacy: .public)': actual \(report.actualSize.width)x\(report.actualSize.height), wants \(report.wrappedIdealSize.width)x\(report.wrappedIdealSize.height)")
            }
        }
    }
}

#if DEBUG
private struct DBTruncationProbeModifier: ViewModifier {
    let id: String
    let outline: Bool

    @State private var actual: CGSize = .zero
    @State private var wrapped: CGSize = .zero
    @State private var singleLine: CGSize = .zero

    private var report: DBTruncationReport? {
        DBTruncationReport.evaluate(id: id, actual: actual, wrappedIdeal: wrapped, singleLineIdeal: singleLine)
    }

    func body(content: Content) -> some View {
        let report = report
        content
            .onGeometryChange(for: CGSize.self) { $0.size } action: { actual = $0 }
            .background {
                content
                    .lineLimit(nil)
                    .minimumScaleFactor(1)
                    .fixedSize(horizontal: false, vertical: true)
                    .hidden()
                    .onGeometryChange(for: CGSize.self) { $0.size } action: { wrapped = $0 }
                    .accessibilityHidden(true)
            }
            .background {
                content
                    .minimumScaleFactor(1)
                    .fixedSize()
                    .hidden()
                    .onGeometryChange(for: CGSize.self) { $0.size } action: { singleLine = $0 }
                    .accessibilityHidden(true)
            }
            .overlay {
                if outline, report != nil {
                    Rectangle()
                        .strokeBorder(Color.red, lineWidth: 1)
                        .allowsHitTesting(false)
                        .accessibilityHidden(true)
                }
            }
            .preference(key: DBTruncationPreferenceKey.self, value: report.map { [$0] } ?? [])
    }
}
#endif
