import CoreGraphics

/// When an iPhone window is wide enough for the unfolded layout (list and detail side by side).
///
/// The iPhone Duo's inner screen is 669 pt wide in portrait and 951 pt in landscape; its cover
/// screen is 466 pt. No other iPhone passes 440 pt in portrait, and the iPhone app is portrait
/// only, so 600 pt splits folded from unfolded with room on both sides.
public enum FoldLayout {
    public static let minWidth: CGFloat = 600

    public static func isUnfolded(width: CGFloat) -> Bool {
        width >= minWidth
    }
}
