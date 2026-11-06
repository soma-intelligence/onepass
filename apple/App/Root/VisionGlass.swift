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

/// visionOS stand-in for SwiftUI's `Glass` (unavailable there): `.regular` and `.interactive()` only
/// pick the call site's spelling, the window's glass already gives the depth.
struct Glass {
    static var regular: Glass { Glass() }
    func interactive(_ isEnabled: Bool = true) -> Glass { self }
}

extension View {
    /// visionOS stand-in for `glassEffect(_:in:)`: the regular material in the same shape.
    func glassEffect(_ glass: Glass = .regular, in shape: some Shape = Capsule()) -> some View {
        background(.regularMaterial, in: shape)
    }
}
#endif
