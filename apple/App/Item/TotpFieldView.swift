import DesignKit
import SwiftUI
import VaultKit

/// The current one-time code ("123 • 456") and its countdown ring, refreshed every second.
/// The secret itself is never shown here.
struct TotpCodeView: View {
    let secret: String
    var compact = false

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            if let code = Self.code(secret, at: context.date) {
                HStack(spacing: 10) {
                    Text(verbatim: Self.grouped(code.code))
                        .font(compact ? .callout.monospacedDigit() : .title3.monospacedDigit().weight(.medium))
                        .contentTransition(.numericText())
                        .accessibilityLabel(Text("Code à usage unique"))
                        .accessibilityValue(Text(verbatim: code.code))
                    TotpRing(remaining: Int(code.remaining), period: Int(code.period))
                }
            } else {
                Text("Secret invalide : colle la clé base32 ou l'URI otpauth://.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Cheap core call (HMAC), fine on the main actor.
    static func code(_ secret: String, at date: Date) -> FfiTotpCode? {
        try? totpNow(secretOrUri: secret, unixSeconds: UInt64(max(0, date.timeIntervalSince1970)))
    }

    /// "123456" gives "123 • 456" (mockup); other lengths are split in two halves.
    static func grouped(_ code: String) -> String {
        guard code.count >= 6 else { return code }
        let half = code.index(code.startIndex, offsetBy: code.count / 2)
        return String(code[..<half]) + " • " + String(code[half...])
    }
}

/// Detail row of a one-time code field: label, live code with its ring, Copier (the code).
struct TotpFieldView: View {
    let field: FfiField
    let onCopy: (String) -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(field.label).font(.footnote).foregroundStyle(.secondary)
                TotpCodeView(secret: field.value.text)
            }
            Spacer(minLength: 0)
            Button {
                let now = Date()
                if let code = TotpCodeView.code(field.value.text, at: now) { onCopy(code.code) }
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(Text("Copier le code"))
            .accessibilityIdentifier("field.copy.\(field.id)")
        }
    }
}
