import DesignKit
import SwiftUI

/// Covers the whole window while the scene is not active (app switcher snapshot, Control Center,
/// system sheets), so no vault content is ever captured (spec 9). Opaque on purpose: a blur would
/// still let shapes and colors through.
struct PrivacyShield: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.background)
            AppGlyph(size: 88)
        }
        .ignoresSafeArea()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("OnePass masqué"))
    }
}

#Preview("PrivacyShield") {
    PrivacyShield()
}
