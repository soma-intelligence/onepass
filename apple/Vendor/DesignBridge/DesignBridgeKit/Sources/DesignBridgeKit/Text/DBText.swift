import SwiftUI

/// Constants and the pure fit rule behind `dbText` (UX-TEXT-01, UX-DT-01).
public enum DBTextFit {
    /// The smallest scale text may shrink to.
    public static let minimumScaleFloor: CGFloat = 0.7
    public static let defaultMinimumScale: CGFloat = 0.85
    /// Share of each line that word wrapping really fills; leaves room for ragged lines.
    public static let wrapEfficiency: CGFloat = 0.9

    /// The width a text needs when it may wrap to `maxLines` lines and then
    /// shrink to `minimumScale`. It fits a width `w` when this is `<= w`.
    public static func budgetWidth(singleLineWidth: CGFloat, maxLines: Int, minimumScale: CGFloat) -> CGFloat {
        let lines = CGFloat(max(1, maxLines))
        let scale = minimumScale.clamped(to: minimumScaleFloor...1)
        return singleLineWidth * scale / (lines * wrapEfficiency)
    }

    public static func fits(singleLineWidth: CGFloat, availableWidth: CGFloat, maxLines: Int, minimumScale: CGFloat) -> Bool {
        budgetWidth(singleLineWidth: singleLineWidth, maxLines: maxLines, minimumScale: minimumScale) <= availableWidth
    }
}

public extension View {
    /// Text that never clips: it wraps first, up to `maxLines`, then shrinks
    /// down to `minimumScale` (never below 0.7). Without `maxLines` it wraps freely.
    ///
    /// Keep `minimumScale` for short single-line values such as amounts; prose
    /// should wrap (UX-TEXT-01).
    func dbText(maxLines: Int? = nil, minimumScale: CGFloat = DBTextFit.defaultMinimumScale) -> some View {
        self
            .lineLimit(maxLines)
            .minimumScaleFactor(maxLines == nil ? 1 : minimumScale.clamped(to: DBTextFit.minimumScaleFloor...1))
            .allowsTightening(true)
            .fixedSize(horizontal: false, vertical: true)
    }

    /// Wraps, then shrinks, then switches to `fallback` when even that would
    /// not fit: a shorter string or a vertical layout. Uses `ViewThatFits`.
    ///
    /// ```swift
    /// Text("Transfer to savings account").dbText(maxLines: 2) {
    ///     Text("Transfer").dbText()
    /// }
    /// ```
    func dbText<Fallback: View>(
        maxLines: Int,
        minimumScale: CGFloat = DBTextFit.defaultMinimumScale,
        @ViewBuilder fallback: () -> Fallback
    ) -> some View {
        ViewThatFits(in: .horizontal) {
            DBTextBudgetLayout(maxLines: maxLines, minimumScale: minimumScale) {
                self.dbText(maxLines: maxLines, minimumScale: minimumScale)
            }
            fallback()
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Reports an ideal width that accounts for wrapping and scaling, so
/// `ViewThatFits` keeps the first choice while wrapped, scaled text still fits.
private struct DBTextBudgetLayout: Layout {
    let maxLines: Int
    let minimumScale: CGFloat

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        guard let child = subviews.first else { return .zero }
        if proposal.width == nil {
            let ideal = child.sizeThatFits(.unspecified)
            let width = DBTextFit.budgetWidth(singleLineWidth: ideal.width, maxLines: maxLines, minimumScale: minimumScale)
            return CGSize(width: width, height: ideal.height)
        }
        return child.sizeThatFits(proposal)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        subviews.first?.place(at: bounds.origin, proposal: ProposedViewSize(bounds.size))
    }
}

/// Lays children out in a row, and in a column when the row does not fit or
/// at accessibility text sizes (UX-DT-01). The layout half of `dbText`.
public struct DBAdaptiveStack<Content: View>: View {
    private let spacing: CGFloat?
    private let content: Content
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    public init(spacing: CGFloat? = nil, @ViewBuilder content: () -> Content) {
        self.spacing = spacing
        self.content = content()
    }

    public var body: some View {
        if dynamicTypeSize.isAccessibilitySize {
            VStack(alignment: .leading, spacing: spacing) { content }
        } else {
            ViewThatFits(in: .horizontal) {
                HStack(spacing: spacing) { content }
                VStack(alignment: .leading, spacing: spacing) { content }
            }
        }
    }
}
