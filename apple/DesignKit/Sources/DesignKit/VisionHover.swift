import SwiftUI

extension View {
    /// The system hover highlight where the eyes rest (visionOS) on rows, tiles and custom buttons.
    /// Elsewhere the view is unchanged: iPad and Mac keep their own pointer behaviour.
    @ViewBuilder public func visionHoverEffect() -> some View {
        #if os(visionOS)
        hoverEffect()
        #else
        self
        #endif
    }
}
