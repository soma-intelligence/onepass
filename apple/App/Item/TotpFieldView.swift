import DesignKit
import SwiftUI
import VaultKit

/// The current one-time code ("123 • 456") and its countdown (a ring in the editor, a ring pill in
/// the detail), refreshed every second. The secret itself is never shown here.
struct TotpCodeView: View {
    let secret: String
    var compact = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// RX look: the 28 pt code in two groups and the 24 pt timer ring.
    @Environment(\.rxCards) private var rxCards

    var body: some View {
        #if os(iOS) || os(macOS)
        if rxCards, !compact {
            rxBody
        } else {
            classicBody
        }
        #else
        classicBody
        #endif
    }

    /// The RX code row (verification code card): the two groups of digits at 28 pt (tabular
    /// figures, no leading bearing beyond the font's own), a fixed 8 pt gap between them, then the
    /// 24 pt timer ring centred on the digits. The row starts exactly at the value's leading edge,
    /// under the field label.
    private var rxBody: some View {
        TimelineView(.animation(minimumInterval: reduceMotion ? 1.0 : 1.0 / 30)) { context in
            if let code = Self.code(secret, at: context.date) {
                let exact = Self.exactRemaining(period: code.period, at: context.date)
                let groups = Self.groups(code.code)
                HStack(alignment: .center, spacing: 0) {
                    HStack(spacing: Self.rxGroupGap) {
                        ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                            Text(verbatim: group)
                                .contentTransition(.numericText())
                        }
                    }
                    .font(.system(size: Self.rxDigitSize, weight: .semibold).monospacedDigit())
                    .foregroundStyle(Theme.RX.Palette.textPrimary.color)
                    .lineLimit(1)
                    .fixedSize()
                    .animation(.snappy(duration: 0.35), value: code.code)
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(Text("term.oneTimeCode"))
                    .accessibilityValue(Text(verbatim: code.code))
                    Spacer(minLength: Theme.RX.Space.s)
                    RXTimerRing(remaining: Int(code.remaining), fraction: exact / Double(max(code.period, 1)))
                }
                .frame(height: Self.rxRowHeight)
            } else {
                Text("item.invalidSecretPasteBase32")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Digit size, gap between the two groups and row height of the RX code.
    static let rxDigitSize: CGFloat = 28
    static let rxGroupGap: CGFloat = 8
    static let rxRowHeight: CGFloat = 34

    /// "538262" gives ["538", "262"]; other lengths of 6 or more are split in halves, a shorter
    /// code stays whole.
    static func groups(_ code: String) -> [String] {
        guard code.count >= 6 else { return [code] }
        let half = code.index(code.startIndex, offsetBy: code.count / 2)
        return [String(code[..<half]), String(code[half...])]
    }

    private var classicBody: some View {
        // Every frame while shown, so the ring drains smoothly; once a second with Reduce Motion.
        TimelineView(.animation(minimumInterval: reduceMotion ? 1.0 : 1.0 / 30)) { context in
            if let code = Self.code(secret, at: context.date) {
                HStack(spacing: Theme.Space.m) {
                    Text(verbatim: Self.grouped(code.code))
                        .font(compact ? .callout.monospacedDigit() : .title3.monospacedDigit())
                        .contentTransition(.numericText())
                        .animation(.snappy(duration: 0.35), value: code.code)
                        .accessibilityLabel(Text("term.oneTimeCode"))
                        .accessibilityValue(Text(verbatim: code.code))
                    if compact {
                        TotpRing(remaining: Int(code.remaining), period: Int(code.period), exact: reduceMotion ? nil : Self.exactRemaining(period: code.period, at: context.date))
                    } else {
                        TotpCountdown(remaining: Int(code.remaining), period: Int(code.period), exact: reduceMotion ? nil : Self.exactRemaining(period: code.period, at: context.date))
                    }
                }
            } else {
                Text("item.invalidSecretPasteBase32")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Seconds left in the current period, with their fraction.
    static func exactRemaining(period: UInt32, at date: Date) -> Double {
        let length = Double(max(period, 1))
        return length - date.timeIntervalSince1970.truncatingRemainder(dividingBy: length)
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

/// The RX countdown: 24 pt, a faint track and the accent arc draining (2.5 pt), the seconds in
/// the middle (Caption 2, tabular); red over the last five seconds.
private struct RXTimerRing: View {
    let remaining: Int
    let fraction: Double

    var body: some View {
        let color = remaining <= 5 ? Theme.RX.Palette.negative.color : Theme.RX.Palette.accent.color
        ZStack {
            Circle().stroke(Theme.RX.Palette.textTertiary.color.opacity(0.4), lineWidth: 2.5)
            Circle()
                .trim(from: 0, to: min(max(fraction, 0), 1))
                .stroke(color, style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text(remaining, format: .number)
                .font(.caption2.weight(.semibold).monospacedDigit())
                .foregroundStyle(remaining <= 5 ? color : Theme.RX.Palette.accentText.color)
        }
        .padding(1.25)
        .frame(width: 24, height: 24)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("encore \(remaining) secondes"))
    }
}

/// Detail row of a one-time code field: label, live code with its countdown pill, Copier (the code).
/// While the screen is captured (iOS, visionOS) the code is drawn as bullets; Copier still works.
struct TotpFieldView: View {
    let field: FfiField
    var captured = false
    let onCopy: (String) -> Void
    @Environment(\.rxCards) private var rxCards

    /// RX: the template's "TOTP" label reads "Code de vérification"; a label the person typed stays.
    private var label: String {
        if rxCards, field.displayLabel.caseInsensitiveCompare("TOTP") == .orderedSame {
            return String(localized: "rx.item.verificationCode")
        }
        return field.displayLabel.detailLabelCase
    }

    var body: some View {
        DetailRow(
            label: label, copyIdentifier: "field.copy.\(field.id)",
            copyLabel: Text("Copier le code"), onCopy: copyCurrent, showsMenu: false
        ) {
            if captured {
                Text(verbatim: FieldRow.mask)
                    .font(.title3.monospacedDigit())
                    .accessibilityLabel(Text("term.oneTimeCode"))
                    .accessibilityValue(Text("item.hidden2"))
            } else {
                TotpCodeView(secret: field.value.text)
            }
        } accessory: {
            EmptyView()
        } menu: {
            EmptyView()
        }
        .centeredOnValue(rxCards)
    }

    private func copyCurrent() {
        if let code = TotpCodeView.code(field.value.text, at: Date()) { onCopy(code.code) }
    }
}
