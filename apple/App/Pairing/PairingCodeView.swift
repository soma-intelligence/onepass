import DesignKit
import SwiftUI

/// The 6-digit code both screens show (spec 2b 5.1 point 5), large, in two groups of three.
struct PairingCodeView: View {
    let code: String

    private var grouped: String {
        guard code.count == 6 else { return code }
        return "\(code.prefix(3)) \(code.suffix(3))"
    }

    var body: some View {
        Text(verbatim: grouped)
            .font(.system(size: Platform.isMac ? 44 : 52, weight: .semibold, design: .monospaced))
            .monospacedDigit()
            .tracking(2)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 22)
            .card()
            .accessibilityLabel(Text("Code de vérification"))
            .accessibilityValue(Text(verbatim: code.map(String.init).joined(separator: " ")))
            .accessibilityIdentifier("pairing.code")
    }
}
