#if os(visionOS)
import SwiftUI

// visionOS has no Liquid Glass button styles (`.glass`, `.glassProminent` are unavailable there):
// the system bordered styles already draw on the window's glass. These stand-ins keep one call
// site per button for every platform; the compiler prefers them over the unavailable declarations.

extension PrimitiveButtonStyle where Self == BorderedButtonStyle {
    /// visionOS stand-in for the Liquid Glass button style.
    static var glass: BorderedButtonStyle { .bordered }
}

extension PrimitiveButtonStyle where Self == BorderedProminentButtonStyle {
    /// visionOS stand-in for the prominent Liquid Glass button style.
    static var glassProminent: BorderedProminentButtonStyle { .borderedProminent }
}
#endif
