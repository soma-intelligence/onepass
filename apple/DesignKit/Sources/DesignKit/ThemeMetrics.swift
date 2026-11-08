import SwiftUI

extension Theme {
    /// The spacing scale. Screens pick from these steps instead of writing a number.
    public enum Space {
        public static let xxs: CGFloat = 2
        public static let xs: CGFloat = 4
        public static let s: CGFloat = 8
        public static let m: CGFloat = 12
        public static let l: CGFloat = 16
        public static let xl: CGFloat = 24
        public static let xxl: CGFloat = 32

        /// Padding inside a card.
        public static let inCard: CGFloat = m
        /// Gap between two sections of a screen.
        public static let betweenSections: CGFloat = xl

        /// Side margin of a screen: 16 pt on a compact width, 20 pt on a regular one (iPad).
        public static func gutter(regularWidth: Bool) -> CGFloat {
            regularWidth ? 20 : l
        }
    }

    /// The corner radius scale.
    public enum Radius {
        public static let chip: CGFloat = 8
        public static let control: CGFloat = 12
        public static let card: CGFloat = 18
        public static let sheet: CGFloat = 26

        /// Radius of a shape inset by `padding` inside a shape of radius `outer`, so the two
        /// corners stay concentric. Never negative.
        public static func nested(outer: CGFloat, padding: CGFloat) -> CGFloat {
            max(outer - padding, 0)
        }
    }

    /// The soft shadow under a card: black at 4%, blurred 12 pt, dropped 4 pt.
    public static let cardShadow: (color: Color, radius: CGFloat, y: CGFloat) =
        (color: .black.opacity(0.04), radius: 12, y: 4)
}
